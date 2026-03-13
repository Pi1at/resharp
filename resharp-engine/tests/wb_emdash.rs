use resharp::Regex;

fn check(pattern: &str, input: &[u8]) {
    let re = Regex::new(pattern).unwrap();
    let matches: Vec<(usize, usize)> = re
        .find_all(input)
        .unwrap()
        .iter()
        .map(|m| (m.start, m.end))
        .collect();

    let rx = regex::bytes::Regex::new(pattern).unwrap();
    let expected: Vec<(usize, usize)> = rx
        .find_iter(input)
        .map(|m| (m.start(), m.end()))
        .collect();

    eprintln!("pattern={pattern:?} input={:?}", String::from_utf8_lossy(input));
    eprintln!("  resharp: {matches:?}");
    eprintln!("  regex:   {expected:?}");
    assert_eq!(matches, expected, "pattern={pattern:?}");
}

#[test]
fn wb_before_emdash() {
    check(r"\b[A-Za-z]+\b", "you\u{2014}them".as_bytes());
}

#[test]
fn wb_between_words_via_emdash() {
    check(r"\b\w+\b", "abc\u{2014}def".as_bytes());
}

#[test]
fn wb_word_class_emdash() {
    check(r"\b[0-9A-Za-z_]+\b", "you\u{2014} you".as_bytes());
}

#[test]
fn wb_after_high_byte() {
    check(r"\b[A-Za-z]+\b", &[0x94, b'y', b'o', b'u']);
}
