// run as: cargo test --package resharp --test wb_en_sampled -- --nocapture
use resharp::Regex;
use std::path::Path;

#[test]
fn wb_word_pattern_en_sampled() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../data/haystacks/en-sampled.txt");
    let haystack = std::fs::read(&path).unwrap();
    let pattern = r"\b[0-9A-Za-z_]+\b";

    let re = Regex::new(pattern).unwrap();
    let matches: Vec<(usize, usize)> = re
        .find_all(&haystack)
        .unwrap()
        .iter()
        .map(|m| (m.start, m.end))
        .collect();

    let rx = regex::bytes::Regex::new(pattern).unwrap();
    let expected: Vec<(usize, usize)> = rx
        .find_iter(&haystack)
        .map(|m| (m.start(), m.end()))
        .collect();

    eprintln!("resharp: {} matches", matches.len());
    eprintln!("regex:   {} matches", expected.len());

    if matches.len() != expected.len() {
        let min_len = matches.len().min(expected.len());
        for i in 0..min_len {
            if matches[i] != expected[i] {
                let (rs, re_end) = matches[i];
                let (xs, xe) = expected[i];
                eprintln!("first diff at index {i}:");
                eprintln!("  resharp: ({rs}, {re_end}) = {:?}", String::from_utf8_lossy(&haystack[rs..re_end]));
                eprintln!("  regex:   ({xs}, {xe}) = {:?}", String::from_utf8_lossy(&haystack[xs..xe]));
                let ctx_start = rs.saturating_sub(30);
                let ctx_end = (xe + 30).min(haystack.len());
                eprintln!("  context: ...{:?}...", String::from_utf8_lossy(&haystack[ctx_start..ctx_end]));
                // show a few more
                for j in i+1..(i+5).min(min_len) {
                    if matches[j] != expected[j] {
                        let (rs, re_end) = matches[j];
                        let (xs, xe) = expected[j];
                        eprintln!("  diff at {j}: resharp=({rs},{re_end})={:?} regex=({xs},{xe})={:?}",
                            String::from_utf8_lossy(&haystack[rs..re_end]),
                            String::from_utf8_lossy(&haystack[xs..xe]));
                    }
                }
                break;
            }
        }
        if min_len == matches.len() && min_len < expected.len() {
            let (xs, xe) = expected[min_len];
            eprintln!("regex has extra match at index {min_len}: ({xs}, {xe}) = {:?}",
                String::from_utf8_lossy(&haystack[xs..xe]));
        }
    }

    assert_eq!(matches.len(), expected.len(), "match count mismatch");
    assert_eq!(matches, expected, "match spans differ");
}
