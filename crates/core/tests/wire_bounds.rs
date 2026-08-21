use sandy_core::{MAX_WIRE_BYTES, WireError, decode_launch};

#[test]
fn rejects_oversized_wire_input_before_deserializing() {
    let input = vec![b' '; MAX_WIRE_BYTES + 1];
    assert!(matches!(decode_launch(&input), Err(WireError::TooLarge(_))));
}
