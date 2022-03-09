
import subprocess
import platform
import re


#rawInterfaceString = subprocess.check_output(['ipconfig','/all'])
#print rawInterfaceString

#indices = [index for index in range(len(rawInterfaceString)) if rawInterfaceString.startswith('Description', index)]

# --> range(len(rawInterfaceString)) creeaza un range de la 0 (default fara alte argumente) pana inainte de numarul pasat ca argument.
#     de exemplu daca len(rawInterfaceString) este 4098 atunci secventa de numere returnata de range este de la 0 la 4097
# --> index for index - inseamna - primul index este elementul ce se va introduce in lista
#                                - al doilea index este fiecare element din loop-ul for
#                                - "adauga index in lista pentru fiecare element (index) din range"
#  --> if rawInterfaceString.startswith('Description', index) - face filtrarea 
#                                                             - adauga index in lista daca conditia lui if e True 
#  --> startswith('Description', index) -> returneaza boolean in functie daca stringul rawInterfaceString incepe cu 'Description' incepand cautarea la index
#      se va verifica deci daca la fiecare index din rawInterfaceString incepe stringul Description, si daca incepe, indexul va fi adaugat in lista
#  --> "fiecare element din lista range (al doilea index) va fi adaugat in lista noua formata din elementele <primul index> daca la acel index incepe stringul Description"


#for index in indices:
#    rawInterfaceString.find('Physical Address', index)
#    print rawInterfaceString[index:rawInterfaceString.find('Physical Address', index)]
#print range(len(rawInterfaceString))

rawInterfaceString = subprocess.check_output(['ipconfig','/all'])
liste =  re.findall('\Description[^\r]*', rawInterfaceString)

for el in liste:
    liste[liste.index(el)] = el[el.find(":") + 2:]

print liste