import uuid
import ast

print(str(uuid.uuid4()))

nested_list = [['사과', '바나나', '딸기'], ['사과', '바나나', '딸기'], ['사과', '바나나', '딸기']]

result_string = str(nested_list)

my_list = ast.literal_eval(result_string)
print(my_list[0])
print(type(my_list[0]))
_list = "[34, 12, 18, 27, 45, 14, 17, 13, 39, 20]"
_list2 = [34, 12, 13, 18, 27, 14, 45, 33, 37, 40]

from typing import cast
extract_num_str = cast(str, _list)
_full_int_list = ast.literal_eval(extract_num_str)

print(_full_int_list)
