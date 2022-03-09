from os import system

def clearConsole(os):
    if os == 'Linux':
        system('clear')
    elif os == 'Windows':
        system('cls')

def titleFormatter(title, level):
    if level == 1:
        return '#'*(26+len(title))+'\n'+12*'#'+f' {title} '+12*'#'+'\n'+'#'*(26+len(title))+'\n'
    elif level == 2:
        return '+'+'-'*(24+len(title))+'+'+'\n'+'+'+11*'-'+f' {title} '+11*'-'+'+'+'\n'+'+'+'-'*(24+len(title))+'+'+'\n'
    elif level == 3:
        return '|'+(6*'-')+'|'+f' {title} '+'|'+6*'-'+'|' + '\n'
    elif level == 4:
        return '#'*(26+len(title))+'\n'+12*'#'+f' {title} '+12*'#'+'\n'+'#'*(26+len(title))+'\n'