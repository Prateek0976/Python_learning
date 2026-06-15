import ctypes

x = 10
ptr_x = x
print(f"Value: {x}, Address: {id(x)}")

my_list = [1, 2, 3]
ptr_list = my_list
ptr_list.append(4)
print(f"Original list after modification: {my_list}")

data = {'name': 'Alice', 'age': 25}
ptr_data = data
print(f"Access through pointer: {ptr_data['name']}")

array = (ctypes.c_int * 3)(10, 20, 30)
ptr_array = ctypes.cast(array, ctypes.POINTER(ctypes.c_int))
for i in range(3):
    print(f"Array[{i}] = {ptr_array[i]}")

null_ptr = None
if null_ptr is None:
    print("Null pointer check passed")
