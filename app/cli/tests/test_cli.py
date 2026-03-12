from click.testing import CliRunner

from cli.main import main


class TestCLIGroup:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "intrusion-inspector" in result.output.lower()

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output


class TestCollectCommand:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["collect", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output
        assert "--profile" in result.output

    def test_missing_required_output(self):
        runner = CliRunner()
        result = runner.invoke(main, ["collect"])
        assert result.exit_code != 0
        assert "Missing" in result.output or "required" in result.output.lower()


class TestTriageCommand:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["triage", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output
        assert "--profile" in result.output
        assert "--format" in result.output


class TestVerifyCommand:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["verify", "--help"])
        assert result.exit_code == 0
        assert "--input" in result.output

    def test_nonexistent_path_fails(self):
        runner = CliRunner()
        result = runner.invoke(main, ["verify", "--input", "/nonexistent/path"])
        assert result.exit_code != 0


class TestReportCommand:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["report", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--input" in result.output
