import csv
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("check_requirements", Path(__file__).resolve().parents[1] / "scripts/check-requirements.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class RequirementsGate(unittest.TestCase):
    def check_row(self, changes):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prd = root / "prd.md"
            prd.write_text("| REQ-TEST-01 | A required behavior | A real result |\n", encoding="utf-8")
            row = {field: "" for field in checker.REQUIRED}
            row.update(requirement_id="REQ-TEST-01", priority="MUST", implementation_status="IN_PROGRESS", verification_status="NOT_RUN")
            row.update(changes)
            matrix = root / "matrix.csv"
            with matrix.open("w", encoding="utf-8", newline="") as output:
                writer = csv.DictWriter(output, fieldnames=sorted(checker.REQUIRED))
                writer.writeheader()
                writer.writerow(row)
            return checker.validate(root, matrix, prd)[0]

    def test_unverified_work_is_valid_but_not_verified(self):
        self.assertEqual(self.check_row({}), [])

    def test_pass_without_evidence_is_rejected(self):
        self.assertTrue(self.check_row({"implementation_status": "VERIFIED", "verification_status": "PASS"}))

    def test_mandatory_requirement_cannot_be_removed_or_skipped(self):
        for fields in [{"priority": "OPTIONAL"}, {"verification_status": "N_A"}, {"verification_status": "SKIP"}, {"requirement_id": "REQ-OTHER-01"}]:
            self.assertTrue(self.check_row(fields))

    def test_blocked_requires_reason_and_paths_must_exist(self):
        self.assertTrue(self.check_row({"verification_status": "BLOCKED"}))
        self.assertTrue(self.check_row({"evidence_paths": "../../outside.txt"}))
        self.assertTrue(self.check_row({"evidence_paths": "not-created.txt"}))
        self.assertEqual(self.check_row({"verification_status": "BLOCKED", "blocker": "No authorized Windows RDP target"}), [])


if __name__ == "__main__":
    unittest.main()
