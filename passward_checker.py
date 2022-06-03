#importing modules
import requests #for requests
import hashlib #for hashing 
import sys #for giving runtime arguments


# requesting to the pwned password server
def request_api_data(query_char):
    #url of the API endpoint/ site
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    #requesting data
    res = requests.get(url)
    #checking wheather the request completed successfully or not
    if res.status_code != 200:
        raise RuntimeError(f'Error Featching : {res.status_code} check the API and try again.' )
    return res

# counting the number of password leaks : number
def get_password_leaks_count(hashes,hash_to_check):
    #separating the number of leaks and Hash
    hashes = (line.split(':')for line in hashes.text.splitlines())
    # checking each hash to see if it matcher our hash
    for h, counts in hashes:
        if h == hash_to_check:
            #returning number of leaks
            return counts
    #if no match found return 0
    return 0

# converting password in hashes 
def pwned_api_check(password):
    #sha1 hasing the password
    passward_sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    #spliting of first 5 and the remaining characters
    first_5_char, tail = passward_sha1[:5], passward_sha1[5:]
    response = request_api_data(first_5_char)
    # print(first_5_char,tail,response)
    return get_password_leaks_count(response,tail)
    #check wheather the password is available in the API response

# pwned_api_check('haris')     

#looping over all the given passwords
def main(args):
    for passward in args:
        count = pwned_api_check(passward)
        if count:
            print(f'{passward} was found {count} times. Try an other its not secure!')
        else:
            print(f'{passward} was not found. Carry on')

    print('done')

main(sys.argv[1:])