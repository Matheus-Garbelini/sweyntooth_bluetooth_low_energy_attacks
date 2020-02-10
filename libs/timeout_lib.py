from threading import Timer

global_timers = {}

def start_timeout(timer_name, seconds, callback):
    global global_timers
    timer = Timer(seconds, callback)
    global_timers[timer_name] = timer
    timer.daemon = True
    timer.start()
 
def disable_timeout(timer_name):
	global global_timers
	try:
	    timer = global_timers[timer_name]
	    timer.cancel()
	    setattr(timer_name, None)
	except:
		return

def update_timeout(timer_name):
	global global_timers
	try:
	    timer = global_timers[timer_name]
	    if timer:
	        timer.cancel()
	        start_timeout(timer_name, timer.interval, timer.function)
	except:
		return

