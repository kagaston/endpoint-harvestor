import json

import pytest
from pathlib import Path

from evidence import EvidenceIntegrity, create_secure_package, extract_secure_package


class TestEvidenceIntegrity:
    @pytest.fixture()
    def populated_output(self, tmp_path):
        """Create a temp dir with test files, run a full integrity lifecycle, and return the output dir."""
        output_dir = tmp_path / "evidence_output"
        output_dir.mkdir()

        files = {}
        for name, content in [("report.json", '{"key": "value"}'), ("data.csv", "a,b,c\n1,2,3\n")]:
            p = output_dir / name
            p.write_text(content)
            files[name] = p

        integrity = EvidenceIntegrity(output_dir, case_id="CASE-001", examiner="tester")
        integrity.start_collection()
        for p in files.values():
            integrity.register_file(p)
        integrity.finalize(total_artifacts=5)

        return output_dir, files

    def test_manifest_exists(self, populated_output):
        output_dir, _ = populated_output
        assert (output_dir / "manifest.json").is_file()

    def test_manifest_contains_registered_files(self, populated_output):
        output_dir, files = populated_output
        manifest = json.loads((output_dir / "manifest.json").read_text())

        assert manifest["file_count"] == len(files)
        manifest_paths = {entry["file_path"] for entry in manifest["files"]}
        for name in files:
            assert name in manifest_paths

    def test_manifest_entries_have_sha256(self, populated_output):
        output_dir, _ = populated_output
        manifest = json.loads((output_dir / "manifest.json").read_text())

        for entry in manifest["files"]:
            assert "sha256" in entry
            assert len(entry["sha256"]) == 64

    def test_audit_log_exists(self, populated_output):
        output_dir, _ = populated_output
        assert (output_dir / "audit.log").is_file()

    def test_audit_log_contains_start_and_end(self, populated_output):
        output_dir, _ = populated_output
        audit_content = (output_dir / "audit.log").read_text()
        assert "collection_start" in audit_content
        assert "collection_end" in audit_content

    def test_chain_of_custody_exists(self, populated_output):
        output_dir, _ = populated_output
        assert (output_dir / "chain_of_custody.json").is_file()

    def test_chain_of_custody_fields(self, populated_output):
        output_dir, _ = populated_output
        coc = json.loads((output_dir / "chain_of_custody.json").read_text())

        assert coc["case_id"] == "CASE-001"
        assert coc["examiner"] == "tester"
        assert "hostname" in coc
        assert "collection_start" in coc
        assert "collection_end" in coc
        assert "manifest_sha256" in coc
        assert coc["total_artifacts"] == 5
        assert coc["total_files"] == 2

    def test_verify_untampered(self, populated_output):
        output_dir, _ = populated_output
        valid, errors = EvidenceIntegrity.verify(output_dir)
        assert valid is True
        assert errors == []

    def test_verify_detects_tampered_file(self, populated_output):
        output_dir, files = populated_output
        tampered = list(files.values())[0]
        tampered.write_text("TAMPERED CONTENT")

        valid, errors = EvidenceIntegrity.verify(output_dir)
        assert valid is False
        assert len(errors) >= 1
        assert any("HASH MISMATCH" in e for e in errors)

    def test_verify_detects_missing_file(self, populated_output):
        output_dir, files = populated_output
        removed = list(files.values())[0]
        removed.unlink()

        valid, errors = EvidenceIntegrity.verify(output_dir)
        assert valid is False
        assert any("MISSING" in e for e in errors)


class TestSecureOutput:
    @pytest.fixture()
    def source_dir(self, tmp_path):
        src = tmp_path / "source"
        src.mkdir()
        (src / "file1.txt").write_text("hello world")
        (src / "file2.txt").write_text("forensic data")
        sub = src / "subdir"
        sub.mkdir()
        (sub / "nested.txt").write_text("nested content")
        return src

    def test_create_package_returns_path(self, source_dir, tmp_path):
        output = tmp_path / "package.zip"
        result = create_secure_package(source_dir, output_path=output, password="s3cret")
        assert result == output
        assert output.is_file()

    def test_create_package_default_path(self, source_dir):
        result = create_secure_package(source_dir, password="pw")
        expected = source_dir.parent / f"{source_dir.name}_evidence.zip"
        assert result == expected
        assert expected.is_file()

    def test_extract_matches_originals(self, source_dir, tmp_path):
        package = tmp_path / "evidence.zip"
        create_secure_package(source_dir, output_path=package, password="pass123")

        extract_dir = tmp_path / "extracted"
        extract_secure_package(package, extract_dir, password="pass123")

        assert (extract_dir / "file1.txt").read_text() == "hello world"
        assert (extract_dir / "file2.txt").read_text() == "forensic data"
        assert (extract_dir / "subdir" / "nested.txt").read_text() == "nested content"

    def test_unencrypted_package(self, source_dir, tmp_path):
        package = tmp_path / "plain.zip"
        create_secure_package(source_dir, output_path=package)

        extract_dir = tmp_path / "extracted_plain"
        extract_secure_package(package, extract_dir)

        assert (extract_dir / "file1.txt").read_text() == "hello world"

    def test_create_package_empty_dir_raises(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(ValueError, match="No files found"):
            create_secure_package(empty)

    def test_create_package_missing_dir_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            create_secure_package(tmp_path / "nonexistent")
