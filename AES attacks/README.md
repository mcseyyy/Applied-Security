- To run any of the attacks, run the makefile (make) and then ./attack 54515.D

=== Power Attack  
- The power attack usually works with less than 100 traces but I am using 150
  traces in my code  just to be sure that it always recovers the correct key;
  the number of traces can be easily changed by modifying the define at the
  beginning of the code.
  
- In case the power attack fails it just prints a message and does not retry it
  using more traces; I did not have the time to implement the memory
  reallocation in C. In case it fails, the value of AttacksNo defined at the
  beginning of the code should be increased by AttacksNoInc.
  
===  Fault Attack
- My attack targeted the first SubBytes operation as it is a function of both
the key and the message; As a result, the power traces will be highly
dependent on the bytes of the original key.
- Any round of SubBytes could be potentially targeted as long as the power
trace corresponding to it can be identified. Some extra effort would be
needed to revert the round sub-key to the actual key.
- The 10th round of AddRoundKey could also be a potential targeted operation
as it is also dependent on both the (intermediate) message and the 10-th
round key.
    

    
