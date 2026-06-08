from pathlib import Path
from analyzer.utils import sha256_file

def test_sha256(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("abc")
    assert sha256_file(p) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
