import base64
input_str = 'not!valid@base64#'
print('Input:', input_str)
print('Attempting b64decode...')
try:
    print(base64.urlsafe_b64decode(input_str + '==='))
except Exception as e:
    print('Caught:', type(e).__name__, ':', e)
