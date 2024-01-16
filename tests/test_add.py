import unittest
from common import *


class BasicInstructionTest(unittest.TestCase):
    def test_addi(self):
        for val in [0, 1, 50, 256, 0x543210, 0xFFFFFFFF]:
            program = instr_i(Opcode.ADDI, Register.A, val)
            exit_code = exec_program(program, self.assertTrue)
            self.assertIsNotNone(exit_code, "Connection timeout!")
            self.assertEqual(exit_code, val & 0xFF, "Computed the wrong result!")

    def test_multiple_addi(self):
        for vals in [[0] * 16, [1] * 8, [0x50] * 256, [0x543210] * 7, [0x6543210] * 5,
                     [0x1337, 0x69, 0x42, 0x420, 0xbeef]]:
            program = b''
            val_sum = sum(vals)
            for val in vals:
                program += instr_i(Opcode.ADDI, Register.A, val)
            exit_code = exec_program(program, self.assertTrue)
            self.assertIsNotNone(exit_code, "Connection timeout!")
            self.assertEqual(exit_code, val_sum & 0xFF, "Computed the wrong result!")

    def test_add(self):
        for val1, val2 in [(0, 0), (5, 8), (0xFFFFFFFF, 0xFFFFFFFF), (0xFFFFFFFF, 1)]:
            program = instr_i(Opcode.ADDI, Register.A, val1) + instr_i(Opcode.ADDI, Register.B, val2) + instr_r(
                Opcode.ADD, Register.A, Register.B)
            exit_code = exec_program(program, self.assertTrue)
            self.assertIsNotNone(exit_code, "Connection timeout!")
            self.assertEqual(exit_code, (val1 + val2) & 0xFF, "Computed the wrong result!")


if __name__ == '__main__':
    unittest.main()
