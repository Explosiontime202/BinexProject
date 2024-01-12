import unittest
from common import *


class BasicInstructionTest(unittest.TestCase):
    def test_addi(self):
        for val in [0, 1, 50, 256, 0x543210, 0xFFFFFFFF]:
            program = instr_i(Opcode.ADDI, Register.A, val)
            exit_code = exec_program(program)
            self.assertIsNotNone(exit_code, "Connection timeout!")
            self.assertEqual(exit_code, val & 0xFF, "Computed the wrong result!")


if __name__ == '__main__':
    unittest.main()
