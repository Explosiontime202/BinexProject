import unittest
from common import *


class BasicInstructionTest(unittest.TestCase):
    def test_addi(self):
        for val in [0, 1, 50, 256, 0x543210, 0xFFFFFFFF]:
            program = instr_i(Opcode.ADDI, Register.A, val)
            self.assertEqual(exec_program(program), val & 0xFF)


if __name__ == '__main__':
    unittest.main()
