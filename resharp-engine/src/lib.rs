//! resharp - a regex engine with all boolean operations and lookarounds,
//! powered by symbolic derivatives and lazy DFA construction.

#![deny(missing_docs)]

pub(crate) mod accel;
pub(crate) mod engine;
pub(crate) mod simd;

#[doc(hidden)]
pub use engine::calc_potential_start;
#[doc(hidden)]
pub use engine::calc_prefix_sets;
#[doc(hidden)]
pub use resharp_algebra::solver::TSetId;

pub use resharp_algebra::nulls::Nullability;
pub use resharp_algebra::NodeId;
pub use resharp_algebra::RegexBuilder;

use std::sync::Mutex;

/// error from compiling or matching a regex.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// parse failure.
    Parse(resharp_parser::ResharpError),
    /// algebra error (unsupported pattern, anchor limit).
    Algebra(resharp_algebra::AlgebraError),
    /// DFA state cache exceeded `max_dfa_capacity`.
    CapacityExceeded,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parse(e) => write!(f, "parse error: {}", e),
            Error::Algebra(e) => write!(f, "{}", e),
            Error::CapacityExceeded => write!(f, "DFA state capacity exceeded"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Parse(e) => Some(e),
            Error::Algebra(e) => Some(e),
            Error::CapacityExceeded => None,
        }
    }
}

impl From<resharp_parser::ResharpError> for Error {
    fn from(e: resharp_parser::ResharpError) -> Self {
        Error::Parse(e)
    }
}

impl From<resharp_algebra::AlgebraError> for Error {
    fn from(e: resharp_algebra::AlgebraError) -> Self {
        Error::Algebra(e)
    }
}

/// lazy DFA engine options.
pub struct EngineOptions {
    /// states to eagerly precompile (0 = fully lazy).
    pub dfa_threshold: usize,
    /// max cached DFA states; clamped to `u16::MAX`.
    pub max_dfa_capacity: usize,
    /// max lookahead context distance (default: 800).
    pub lookahead_context_max: u32,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            dfa_threshold: 0,
            max_dfa_capacity: u16::MAX as usize,
            lookahead_context_max: 800,
        }
    }
}

/// byte-offset range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Match {
    /// inclusive start.
    pub start: usize,
    /// exclusive end.
    pub end: usize,
}

struct RegexInner {
    b: RegexBuilder,
    fwd: engine::LazyDFA,
    rev: engine::LazyDFA,
    nulls_buf: Vec<usize>,
}

/// compiled regex backed by a lazy DFA.
///
/// uses a `Mutex` for mutable DFA state; clone for per-thread matching.
pub struct Regex {
    inner: Mutex<RegexInner>,
    fwd_prefix: Option<accel::FwdPrefixSearch>,
    fwd_prefix_stripped: bool,
    fixed_length: Option<u32>,
    #[allow(dead_code)]
    max_length: Option<u32>,
    empty_nullable: bool,
    fwd_end_nullable: bool,
}

impl Regex {
    /// compile with default options.
    pub fn new(pattern: &str) -> Result<Regex, Error> {
        Self::with_options(pattern, EngineOptions::default())
    }

    /// compile with custom options.
    pub fn with_options(pattern: &str, opts: EngineOptions) -> Result<Regex, Error> {
        let mut b = RegexBuilder::new();
        b.lookahead_context_max = opts.lookahead_context_max;
        let node = resharp_parser::parse_ast(&mut b, pattern)?;
        Self::from_node(b, node, opts)
    }

    /// build from a pre-constructed AST node.
    pub fn from_node(
        mut b: RegexBuilder,
        node: NodeId,
        opts: EngineOptions,
    ) -> Result<Regex, Error> {
        let empty_nullable = b
            .nullability_emptystring(node)
            .has(Nullability::EMPTYSTRING);

        let fwd_start = b.strip_lb(node)?;
        let fwd_end_nullable = b.nullability(fwd_start).has(Nullability::END);
        let rev_start = b.reverse(node)?;
        let ts_rev_start = b.mk_concat(NodeId::TS, rev_start);

        let fixed_length = b.get_fixed_length(node);
        let (min_len, max_len) = b.get_min_max_length(node);
        let max_length = if max_len != u32::MAX {
            Some(max_len)
        } else {
            None
        };
        let has_look = b.contains_look(node);

        let max_cap = opts.max_dfa_capacity.min(u16::MAX as usize);
        let mut fwd = engine::LazyDFA::new(&mut b, fwd_start, max_cap)?;
        let mut rev = engine::LazyDFA::new(&mut b, ts_rev_start, max_cap)?;

        if opts.dfa_threshold > 0 {
            fwd.precompile(&mut b, opts.dfa_threshold);
            rev.precompile(&mut b, opts.dfa_threshold);
        }

        let (fwd_prefix, fwd_prefix_stripped) = if min_len > 0 && !has_look {
            let (fp, stripped) = engine::build_fwd_prefix(&mut b, node)?;
            if fp.is_some() && !stripped && b.is_infinite(node) {
                (None, false)
            } else {
                (fp, stripped)
            }
        } else {
            (None, false)
        };

        rev.compute_skip(&mut b, rev_start)?;

        if fwd_prefix_stripped {
            fwd.compute_fwd_skip(&mut b);
        }

        Ok(Regex {
            inner: Mutex::new(RegexInner {
                b,
                fwd,
                rev,
                nulls_buf: Vec::new(),
            }),
            fwd_prefix,
            fwd_prefix_stripped,
            fixed_length,
            max_length,
            empty_nullable,
            fwd_end_nullable,
        })
    }

    /// (fwd_states, rev_states) count.
    pub fn dfa_stats(&self) -> (usize, usize) {
        let inner = self.inner.lock().unwrap();
        (inner.fwd.state_nodes.len(), inner.rev.state_nodes.len())
    }

    /// whether forward prefix or reverse skip acceleration is active.
    pub fn has_accel(&self) -> (bool, bool) {
        let inner = self.inner.lock().unwrap();
        let fwd = self.fwd_prefix.is_some();
        let rev = inner.rev.prefix_skip.is_some() || inner.rev.can_skip();
        (fwd, rev)
    }

    /// all non-overlapping matches, left-to-right.
    pub fn find_all(&self, input: &[u8]) -> Result<Vec<Match>, Error> {
        if input.is_empty() {
            return if self.empty_nullable {
                Ok(vec![Match { start: 0, end: 0 }])
            } else {
                Ok(vec![])
            };
        }
        if self.fwd_prefix.is_some() {
            if self.fwd_prefix_stripped {
                return self.find_all_fwd_prefix_stripped(input);
            }
            return self.find_all_fwd_prefix(input);
        }
        self.find_all_dfa(input)
    }

    /// debug: dump rev DFA effects_id and effects.
    pub fn effects_debug(&self) -> String {
        let inner = self.inner.lock().unwrap();
        let rev = &inner.rev;
        let mut out = String::new();
        for (i, &eid) in rev.effects_id.iter().enumerate() {
            if eid != 0 {
                let nulls: Vec<String> = rev.effects[eid as usize]
                    .iter()
                    .map(|n| format!("(mask={},rel={})", n.mask.0, n.rel))
                    .collect();
                out += &format!("  state[{}] eid={} nulls=[{}]\n", i, eid, nulls.join(", "));
            }
        }
        out
    }

    /// debug: run only the reverse DFA, return null positions.
    pub fn collect_rev_nulls_debug(&self, input: &[u8]) -> Vec<usize> {
        let inner = &mut *self.inner.lock().unwrap();
        inner.nulls_buf.clear();
        inner
            .rev
            .collect_rev(&mut inner.b, input.len() - 1, input, &mut inner.nulls_buf)
            .unwrap();
        inner.nulls_buf.clone()
    }

    fn find_all_dfa(&self, input: &[u8]) -> Result<Vec<Match>, Error> {
        if self.fwd_end_nullable {
            self.find_all_dfa_inner::<true>(input)
        } else {
            self.find_all_dfa_inner::<false>(input)
        }
    }

    fn find_all_dfa_inner<const FWD_NULL: bool>(
        &self,
        input: &[u8],
    ) -> Result<Vec<Match>, Error> {
        let inner = &mut *self.inner.lock().unwrap();

        let rev_initial_nullable = inner.rev.effects_id[inner.rev.initial as usize] != 0;

        if rev_initial_nullable {
            return Self::find_all_nullable_slow(&mut inner.fwd, &mut inner.b, input);
        }

        inner.nulls_buf.clear();

        inner
            .rev
            .collect_rev(&mut inner.b, input.len() - 1, input, &mut inner.nulls_buf)?;

        let mut matches = Vec::new();
        if let Some(fl) = self.fixed_length {
            let fl = fl as usize;
            let mut last_end = 0;
            for &start in inner.nulls_buf.iter().rev() {
                if start >= last_end && start + fl <= input.len() {
                    matches.push(Match {
                        start,
                        end: start + fl,
                    });
                    last_end = start + fl;
                }
            }
        } else {
            inner
                .fwd
                .scan_fwd_all(&mut inner.b, &inner.nulls_buf, input, &mut matches)?;
        }

        if FWD_NULL
            && inner.nulls_buf.first() == Some(&input.len())
            && matches.last().map_or(true, |m| m.end <= input.len())
        {
            matches.push(Match {
                start: input.len(),
                end: input.len(),
            });
        }

        Ok(matches)
    }

    fn find_all_nullable_slow(
        fwd: &mut engine::LazyDFA,
        b: &mut RegexBuilder,
        input: &[u8],
    ) -> Result<Vec<Match>, Error> {
        let mut matches = Vec::new();
        let mut pos = 0;
        while pos < input.len() {
            let max_end = fwd.scan_fwd(b, pos, input)?;
            if max_end != engine::NO_MATCH && max_end > pos {
                matches.push(Match {
                    start: pos,
                    end: max_end,
                });
                pos = max_end;
            } else {
                matches.push(Match { start: pos, end: pos });
                pos += 1;
            }
        }
        matches.push(Match {
            start: input.len(),
            end: input.len(),
        });
        Ok(matches)
    }

    fn find_all_fwd_prefix(&self, input: &[u8]) -> Result<Vec<Match>, Error> {
        let fwd_prefix = self.fwd_prefix.as_ref().unwrap();
        let mut matches = Vec::new();
        let mut search_start = 0;

        if self.fixed_length == Some(fwd_prefix.len() as u32)
            && fwd_prefix.find_all_literal(input, &mut matches)
        {
            // done
        } else if let Some(fl) = self.fixed_length {
            while let Some(candidate) = fwd_prefix.find_fwd(input, search_start) {
                let end = candidate + fl as usize;
                if end <= input.len() {
                    matches.push(Match {
                        start: candidate,
                        end,
                    });
                    search_start = end;
                } else {
                    break;
                }
            }
        } else {
            let inner = &mut *self.inner.lock().unwrap();
            let prefix_len = fwd_prefix.len();
            while let Some(candidate) = fwd_prefix.find_fwd(input, search_start) {
                let state = inner
                    .fwd
                    .walk_input(&mut inner.b, candidate, prefix_len, input)?;
                if state != 0 {
                    let max_end = inner.fwd.scan_fwd_from(
                        &mut inner.b,
                        state,
                        candidate + prefix_len,
                        input,
                    )?;
                    if max_end != engine::NO_MATCH && max_end > candidate {
                        matches.push(Match {
                            start: candidate,
                            end: max_end,
                        });
                        search_start = max_end;
                        continue;
                    }
                }
                search_start = candidate + 1;
            }
        }

        Ok(matches)
    }

    fn find_all_fwd_prefix_stripped(&self, input: &[u8]) -> Result<Vec<Match>, Error> {
        let fwd_prefix = self.fwd_prefix.as_ref().unwrap();
        let inner = &mut *self.inner.lock().unwrap();
        let prefix_len = fwd_prefix.len();
        let num_mt = inner.fwd.num_minterms as usize;
        let initial = inner.fwd.initial;
        // ensure initial state center transitions are compiled for backward scan
        inner.fwd.precompile_state(&mut inner.b, initial)?;
        let mut matches = Vec::new();
        let mut search_start = 0;

        while let Some(candidate) = fwd_prefix.find_fwd(input, search_start) {
            // walk prefix using center transitions (not begin_table)
            let mut state = initial;
            for i in 0..prefix_len {
                let mt = inner.fwd.minterms_lookup[input[candidate + i] as usize] as u32;
                state = inner.fwd.lazy_transition(&mut inner.b, state, mt)?;
                if state == engine::DFA_DEAD {
                    break;
                }
            }
            if state == engine::DFA_DEAD {
                search_start = candidate + 1;
                continue;
            }
            let max_end = inner.fwd.scan_fwd_from(
                &mut inner.b,
                state as u32,
                candidate + prefix_len,
                input,
            )?;
            if max_end == engine::NO_MATCH {
                search_start = candidate + 1;
                continue;
            }
            // scan backward: extend match start while initial state stays alive
            let mut match_start = candidate;
            while match_start > search_start {
                let b = input[match_start - 1];
                let mt = inner.fwd.minterms_lookup[b as usize] as usize;
                let delta = initial as usize * num_mt + mt;
                let in_bounds = delta < inner.fwd.center_table.len();
                let ct_val = if in_bounds { inner.fwd.center_table[delta] } else { 0 };
                if in_bounds && ct_val > engine::DFA_DEAD {
                    match_start -= 1;
                } else {
                    break;
                }
            }
            if max_end > match_start {
                matches.push(Match {
                    start: match_start,
                    end: max_end,
                });
                search_start = max_end;
            } else {
                search_start = candidate + 1;
            }
        }

        Ok(matches)
    }

    /// longest match anchored at position 0, forward DFA only.
    pub fn find_anchored(&self, input: &[u8]) -> Result<Option<Match>, Error> {
        if input.is_empty() {
            return if self.empty_nullable {
                Ok(Some(Match { start: 0, end: 0 }))
            } else {
                Ok(None)
            };
        }
        let inner = &mut *self.inner.lock().unwrap();
        let max_end = inner.fwd.scan_fwd(&mut inner.b, 0, input)?;
        if max_end != engine::NO_MATCH {
            Ok(Some(Match {
                start: 0,
                end: max_end,
            }))
        } else {
            Ok(None)
        }
    }

    /// whether the pattern matches anywhere in the input.
    pub fn is_match(&self, input: &[u8]) -> Result<bool, Error> {
        if input.is_empty() {
            return Ok(self.empty_nullable);
        }
        let inner = &mut *self.inner.lock().unwrap();
        if inner.rev.effects_id[inner.rev.initial as usize] != 0 {
            return Ok(true);
        }
        inner
            .rev
            .any_nullable_rev(&mut inner.b, input.len() - 1, input)
    }
}
