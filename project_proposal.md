# Project Proposal
## Story
*This is just for fun, the real description is in the next chapter :D*

A startup offers an emulation service with a JIT-engine for a custom ISA. As they are just starting,
the ISA is very small and does not yet support jumps or any other control-flow changing operations. Thus, it is just a
glorified pocket calculator.
There pricing scheme is a freemium model: In the free tier, the generated code is in a seccomp jail which requires a 
fork everytime a new program is executed. Thus, if one pays a premium fee, one can unlock the full program without the 
seccomp jail and so allow for higher performance. As the startup trusts its premium customers, this is no problem.

## Technical description

*Now it gets interesting*

Our challenge is about breaking a simple code generator to enable arbitrary code execution. We intend to include a bug
that allows to generate arbitrary x64 instructions during a faulty optimization. The optimization will fold arithmetic
operations on the same register into one instruction and stores the overall result in a `size_t`. Then the code generator
computes the instruction like that (here as example for an `add`): `(REX.W << 5) + (ADD_OPCODE << 4) + accumulated_value`
(add 32bit immediate to 64bit register). This will lead to an overflow into the opcode, if the accumulated is too large.
Thus, for example `syscall` can be generated.

To make the challenge not too easy, we fork before starting the execution of the executed program and install a seccomp
jail. But for unknown reasons, the startup wants to have a premium tier which does use seccomp to protect from the
generated code. To unlock that mode, the attacker needs to leak the premium key. But as writing to `stdin`, `stdout` or
`stderr` will be prevented (either seccomp or by just closing the according files), one needs to use the exit codes of
the child process. That is the result of the calculation of the program and thus will be printed out so that the user
can see the result of their program.

After that, one can enter the premium key and is basically done: Generate instructions executing the syscall `execve`
with `"/bin/get_flag`. The attacker just needs to figure out, where to put the string, i.e. leaking an address, or using
the libc `/bin/sh`. (it is a constant offset away from the code because the code is mmaped).

PS: all security measures are activated: Full RELRO, Stack Canary, NX, PIE

## Learnings

JIT engines can be vulnerable, especially during optimization passes. Additionally, when generating code at runtime, one
needs to be extra careful.
