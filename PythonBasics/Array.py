# Array sorting in python
arr = []
a = int(input('Enter the number of elements in array :'))
for i in range(0, a):
    print('Enter the element of array')
    arr.append(int(input()))

print('The unsorted array is')
for i in range(0, a):
    print(arr[i])
print('The sorted array is')
arr.sort(reverse=True)
for i in range(0, a):
    print(arr[i])
    
    