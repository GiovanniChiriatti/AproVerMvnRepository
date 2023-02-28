/** at every step increments the seconds 
*/
asm AdvancedClock

import ../StandardLibrary

signature:
	domain Second subsetof Integer
	domain Minute subsetof Integer
	domain Hour subsetof Integer
	controlled seconds: Second
	controlled minutes: Minute    
	controlled hours: Hour

definitions:    
	domain Second = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59}
	domain Minute= {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59}
	domain Hour = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23}

	macro rule r_IncMinHours =  
		par
			if minutes = 59 then
				hours := (hours + 1) mod 24
			endif
			minutes := (minutes + 1) mod 60
		endpar

	main rule r_Main = 
		par
			if seconds = 59 then
				r_IncMinHours[]
			endif
			seconds := (seconds + 1) mod 60
		endpar

default init s0:
	function seconds = 0
	function minutes = 0
	function hours = 0
