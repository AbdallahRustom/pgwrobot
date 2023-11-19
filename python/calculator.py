def sum_subtract(First_Num, Operator, Second_Num):
    if type (First_Num) is not int:
        return "First_num is not vaild"
   
    elif type (Second_Num) is not int:
        return "Second_num is not vaild"
    
    elif Operator == "+" :
        result = First_Num + Second_Num
        
    elif Operator == "-" :
        result = First_Num - Second_Num
    return(result)