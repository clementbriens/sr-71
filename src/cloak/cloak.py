from torrequest import TorRequest
import requests



def request(tr = TorRequest(password='daft')):



tr = TorRequest(password='daft')
response= requests.get('http://ipecho.net/plain')
print ("My Original IP Address:",response.text)


tr.reset_identity() #Reset Tor
response= tr.get('http://ipecho.net/plain')
print ("New Ip Address",response.text)
response= requests.get('http://ipecho.net/plain')
print ("My Original IP Address:",response.text)
