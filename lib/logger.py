from time import gmtime, strftime

colour_red = "\033[1;31m"
colour_blue = "\033[1;34m"
colour_green = "\033[1;32m"
colour_remove= "\033[0m"
good='[+]'
bad='[!]'
info='[#]'

QUIET=False

def RED(string):
	return (colour_red + string + colour_remove)

def BLUE(string):
	return (colour_blue + string + colour_remove)

def GREEN(string):
	return (colour_green + string + colour_remove)

def blue(string):
	if QUIET == False:
		print(BLUE(info)+'\t'+string)
	else:
		pass

def red(string):
	print(RED(bad)+'\t'+string)

def green(string):
	print(GREEN(good)+'\t'+string)

def green_indent(string):
	if QUIET == False:
		print('\t'+GREEN(good)+'\t'+string)
	elif QUIET == True:
		print(GREEN(good)+'\t'+string)

def red_indent(string):
	if QUIET == False:
		print('\t'+RED(bad)+'\t'+string)
	elif QUIET == True:
		pass