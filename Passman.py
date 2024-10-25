import json
import os
import requests
from tkinter import messagebox
import hashlib

currentDirname = os.path.dirname(__file__)
filePath = currentDirname + '/Passman'
print(filePath)

def encryptPassword(password, email, passkey, platform, passmanEmail):
	decryptedPassword = password
	charPassword = []
	binary_value = []
	tempEncryptPassword = []
	encryptionKey = int(passkey)

	for char in decryptedPassword:
		charPassword.append(char)
	
	for char in charPassword:
		binary_value.append(int(bin(ord(char))[2:]))
	
	for value in binary_value:
		tempEncryptPassword.append(value + encryptionKey)
		
	encrypted_data = {"Platform": platform,"Username/Email": email, "Password": tempEncryptPassword}
		
	if os.path.exists(f'{filePath}-{passmanEmail}.json'):
		with open(f'{filePath}-{passmanEmail}.json', 'r') as file:
			existing_data = json.load(file)
		existing_data.append(encrypted_data)
		with open(f'{filePath}-{passmanEmail}.json', 'w') as file:
			json.dump(existing_data, file, indent=4)
	else:
		with open(f'{filePath}-{passmanEmail}.json', 'w') as file:
			json.dump([encrypted_data], file, indent=4)

def encryptPassman(password, email, passkey, platform):
	decryptedPassword = password
	charPassword = []
	binary_value = []
	str_to_int_convert = []
	tempEncryptPassword = []
	encryptionKey = int(passkey)

	print(encryptionKey)
	print(type(encryptionKey))

	for char in decryptedPassword:
		charPassword.append(char)
	
	for char in charPassword:
		binary_value.append(int(bin(ord(char))[2:]))
	
	for value in binary_value:
		tempEncryptPassword.append(value + encryptionKey)

	encryptionKey = str(encryptionKey)

	hashedPasskey = hashlib.sha256(encryptionKey.encode()).hexdigest()
		
	encrypted_data = {"Platform": platform,"Username/Email": email, "Password": tempEncryptPassword, "Passkey": hashedPasskey}
		
	if os.path.exists(f'{filePath}-{email}.json'):
		with open(f'{filePath}-{email}.json', 'r') as file:
			existing_data = json.load(file)
		existing_data.append(encrypted_data)
		with open(f'{filePath}-{email}.json', 'w') as file:
			json.dump(existing_data, file, indent=4)
	else:
		with open(f'{filePath}-{email}.json', 'w') as file:
			json.dump([encrypted_data], file, indent=4)
	
def decryptPassword(email, platform, passkey, passmanEmail):
	binaryList = []
	passwordBinary = []
	passwordChar = []
	char = []
	password = ''
	passkey = int(passkey)
	
	with open(f'{filePath}-{passmanEmail}.json', 'r') as file:
		data = json.load(file)
	
	for entry in data:
		if entry['Username/Email'] == email and entry['Platform'] == platform:
			intBinaryList = entry['Password']
			for binary in intBinaryList:
				binary = str(binary - passkey)
				char.append(chr(int(binary, 2)))
			password = ''.join(char)
		else:
			pass
			
	return password

def returnEncryptedPassword(password, passkey):
	decryptedPassword = password
	charPassword = []
	binary_value = []
	str_to_int_convert = []
	tempEncryptedPassword = []
	encryptionKey = int(passkey)

	for char in decryptedPassword:
		charPassword.append(char)
	
	for char in charPassword:
		binary_value.append(int(bin(ord(char))[2:]))
	
	for value in binary_value:
		tempEncryptedPassword.append(value + encryptionKey)

	return tempEncryptedPassword

def passwordRecovery(passkey, email, passman_username):

	sender_email = ""
	api_key= ""

	recipent_email = ""
	recipent_email = email
	recoveryPasskey = passkey

	def passwordRecoveryProcess():

		if sender_email == '' or api_key == '':
			messagebox.showerror('Recovery Error!', 'Sender email and SendInBlue API key not set!')

			print(f'{filePath}-{passman_username}.json')

			try:
				if os.path.exists(f'{filePath}-{passman_username}.json'):
					with open(f'{filePath}-{passman_username}.json', 'r') as file:
						data = json.load(file)

					for entry in data:
						if entry['Platform'] == 'Passman':
							password = decryptPassword(passman_username, "Passman", recoveryPasskey, passman_username)

							url = "https://api.sendinblue.com/v3/smtp/email"
							headers = {
								"Content-Type": "application/json",
								"api-key": api_key
							}
							payload = {
								"sender": {"email": sender_email},
								"to": [{"email": recipent_email}],
								"subject": "Password Recovery!",
								"htmlContent": f"This is your Password: {password}"
							}
							response = requests.post(url, headers=headers, json=payload)
							if response.status_code == 201:
								print("Email sent successfully.")
								messagebox.showinfo("Success!", "Password sent to recovery email!")
							else:
								print("Failed to send email. Error:", response.text)
						else:
							messagebox.showerror('Passman unaccessbile!', "No valid Passman Account found!")

				else:
					messagebox.showerror('Passman unaccessbile!', "No valid Passman Account found!")
			except UnboundLocalError:
				messagebox.showerror('Recovery Error!', 'Passman Unaccessible!')

	if __name__ == "__main__":
		api_key = api_key
		sender_email = sender_email
		recipient_email = recipent_email
		subject = "Password Recovery"
		message = "<p>This is your Password: {password}</p>"

	passwordRecoveryProcess()
