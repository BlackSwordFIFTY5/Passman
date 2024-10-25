#importing relevent libraries
import tkinter as tk
import Passman as pm
from tkinter import messagebox
import json
import os
import hashlib

#file path to the Passman.json file. self configured, previously you had to configure it yourself.
currentDirname = os.path.dirname(__file__)
filePath = currentDirname + '/Passman'

#toggles show password. shows plain text if true, asterisks if false
def toggle_show_password(passwordEntry):
    if show_password.get():
        passwordEntry.config(show="")
    else:
        passwordEntry.config(show="*")

#initializing the root Tkinter window "Mainmenu"
mainmenu = tk.Tk()

#function checks to see if Passman.json exists, if it exists then the user can just login with their passman credentials, if not then it prompts user to create an account to create a Passman file
def dirCheck(passmanEmail, passmanPassword, passmanPasskey, passman):
	print(f'{filePath}-{passmanEmail}.json')
	if os.path.exists(f'{filePath}-{passmanEmail}.json'):
		with open(f'{filePath}-{passmanEmail}.json', 'r') as file:
			data = json.load(file)
		for entry in data:
			if entry['Platform'] == 'Passman':
				credentialsCheck(passmanEmail, passmanPassword, passmanPasskey, passman)
				break
		else:
			confirmation = messagebox.askyesno("Warning!", "No Passman account associated with provided credentials! Do you wish to create one?")

			if confirmation:
				createPassmanAcc()
	else:
		confirmation = messagebox.askyesno("Warning!", "No Passman account associated with provided credentials! Do you wish to create one?")

		if confirmation:
			createPassmanAcc()


#the lack of a Passman file or account prompts this function so a file is created
def createPassmanAcc():

	#redeclaring this function inside of account creation function because one global function doesn't work :|
	def toggle_show_password(passwordEntry):
		if show_password.get():
			passwordEntry.config(show="")
		else:
			passwordEntry.config(show="*")

	mainmenu.withdraw() #once an account creation window is opened the mainmenu window is withdrawn until creation is completed or cancelled
	
	#a new top level window is created above the iconified/withdrawn root window
	addAccWindow = tk.Toplevel()

	#the label that says "Email:" and email entry box
	emailLabel = tk.Label(addAccWindow, text="Email/Username:")
	emailLabel.grid(row=1, column=0)
	emailEntry = tk.Entry(addAccWindow)
	emailEntry.grid(row=1, column=1)

	passkeyLabel = tk.Label(addAccWindow, text="Passkey:")
	passkeyLabel.grid(row=2, column=0)
	passkeyEntry = tk.Entry(addAccWindow)
	passkeyEntry.grid(row=2, column=1)

	#same, the label that says "Password:" and the password entry box
	passwordLabel = tk.Label(addAccWindow, text="Password:")
	passwordLabel.grid(row=3, column=0)
	passwordEntry = tk.Entry(addAccWindow, show="*")
	passwordEntry.grid(row=3, column=1)

	#check box that stores a boolean value and passes it to the "toggle_show_password" function which changes the "show" attribute of the password entry box
	show_password = tk.BooleanVar()
	show_password_checkbox = tk.Checkbutton(addAccWindow, text="Show Password", variable=show_password, command=lambda: (toggle_show_password(passwordEntry)))
	show_password_checkbox.grid(row=4, column=1)

	#button go cancel account creation
	cancelButton = tk.Button(addAccWindow, text="Cancel", command=lambda: [addAccWindow.destroy(), mainmenu.deiconify(), messagebox.showwarning("Warning!", "Account not created! Passman cannot be access without an account!")])
	cancelButton.grid(row=5, column=0)

	#button to add account with the complete credentials
	addAccountBtn = tk.Button(addAccWindow, text="Add Account", command=lambda : [creatingPassmanAcc(passwordEntry.get(), emailEntry.get(), passkeyEntry.get(), addAccWindow)])
	addAccountBtn.grid(row=5, column=1)

#previous function calls this after the "addAccountBtn" is pressed and passes the credentials in the entry boxes
def creatingPassmanAcc(password, email, passkey, addAccWindow):

	error = 0

	try:
		if len(passkey) < 7:
			error = 1
			createPassmanAcc()
			messagebox.showerror("Error", "Passkey has to be above 1111111!")
		else:
			pass
	except ValueError:
			messagebox.showerror("Error", "Passkey must be a number!")
			createPassmanAcc()
			error = 1

	if error == 0:
		#takes user confirmation to complete creation. this specific message box returns a boolean type
		confirmation = messagebox.askyesno("Account Creation", "Are you sure you want to proceed to Passman with these credentials?")

		if confirmation:
			messagebox.showinfo("Success!", "Account created successfully!")
			pm.encryptPassman(password, email, passkey, "Passman")
			addAccWindow.destroy()
			mainmenu.deiconify()
		else:
			messagebox.showwarning("Warning!", "Account not created! Passman cannot be access without an account!")
			addAccWindow.destroy()
			mainmenu.deiconify()
	else:
		messagebox.showerror("Error", "Failed to create an account!")

#once you're back at the main menu and log in, this function is called if a Passman account exists.'
def credentialsCheck(email, password, passkey, platform):

	if os.path.exists(f'{filePath}-{email}.json'):
		with open(f'{filePath}-{email}.json', 'r') as file:
			passmanData = json.load(file)
	else:
		print("File doesn't exist!")

	for entry in passmanData:
		if entry["Platform"] == "Passman":
			passmanPasskey = entry["Passkey"]

	hashedPasskey = hashlib.sha256(passkey.encode()).hexdigest()

	if passmanPasskey == hashedPasskey:
		tempPassword = pm.decryptPassword(email, 'Passman', passkey, email)
		if tempPassword == "":
			wrongCredentials()
		else: 
			if tempPassword == password:
				logInSuccessful(email, password, passkey, platform)
			else:
				wrongCredentials()
	else:
		messagebox.showerror("Error", "Incorrect Passkey!")

#if the entered credentials are wrong, this error message box is prompted and takes thr user back to the log in screen.
def wrongCredentials():
	messagebox.showerror("Error", "Wrong credentials! Please try again.")
	mainmenu.deiconify()

#if log in is successful, this specific message box is prompted along with the passmanWindow function.
def logInSuccessful(email, password, passkey, platform):
	messagebox.showinfo("Success", "Logged in successfully! Welcome to Passman.")
	passmanWindow(email, password, passkey, platform)

#this function creates separate buttons from which you can view your other accounts info.
def passManButtonCreator(window, passmanEmail, passkey, passmanPassword, passmanWindow):
	num = 0
	try:
		with open(f'{filePath}-{passmanEmail}.json', 'r') as file:
			data = json.load(file)
            
		for entry in data:
			num = num + 1 #this counter helps with the placement of the bottom buttons in the window.
			username_email = entry['Username/Email']
			platform = entry['Platform']
			password = pm.decryptPassword(username_email, platform, passkey, passmanEmail)
			passmanButton = tk.Button(window, text=f'{platform}: {username_email}', width=33, command=lambda u=username_email, p=platform, pwd=password: [passManInfoWindow(u, passkey, p, pwd, passmanEmail, passmanPassword, passmanWindow)])
			passmanButton.grid(columnspan=3)

	except FileNotFoundError:
		print(f"{filePath}-{passmanEmail}.json file not found.")
	except json.JSONDecodeError:
		print("Error decoding Passman.json file.")
	return num

#this function does the same as the previous function, this time to delete the selected account's info.
def delAccBtnCreator(window, passmanEmail, passkey, passmanPassword, passmanPlatform, passmanWindow, delAccWindow):
	num = 0

	try:
		with open(f'{filePath}-{passmanEmail}.json', 'r') as file:
			data = json.load(file)
            
		for entry in data:
			num = num + 1 #this counter helps with the placement of the bottom buttons in the window.
			username_email = entry['Username/Email']
			platform = entry['Platform']
			password = entry['Password']
			target_entry = {'Platform' : platform,
				   			'Username/Email' : username_email,
							'Password' : password}
			passmanButton = tk.Button(window, text=f'{platform}:{username_email}', width=33, command=lambda entry=target_entry: deletingAccount(entry, data, passmanEmail, passmanPassword, passmanPlatform, passkey, passmanWindow, delAccWindow))
			passmanButton.grid(columnspan=3)
	except FileNotFoundError:
		print("Passman.json file not found.")
	except json.JSONDecodeError:
		print("Error decoding Passman.json file.")
	return num 
	credentialsCheck(email, password, passkey, platform)

#shows the account info once any of the Passman Account Info buttons are pressed
def passManInfoWindow(usernameEmail, passkey, platform, password, passmanEmail, passmanPassword, passmanWindow):

	#calculates and makes the asterisks as long as the original password
	blank = "*" * len(password)
	
	def toggle_show_password(passwordLabel):
		if show_password.get():
			passwordLabel.config(text=f"Password: {password}")
		else:
			passwordLabel.config(text=f"Password: {blank}")

	#this window shows the information of a selected account
	passManInfoWindow = tk.Toplevel()

	platformLabel = tk.Button(passManInfoWindow, text=platform)
	platformLabel.grid(row=0, columnspan=2)
	
	usernameEmailLabel = tk.Label(passManInfoWindow, text=f"Username/Email: {usernameEmail}")
	usernameEmailLabel.grid(row=1, columnspan=2)
	
	passwordLabel = tk.Label(passManInfoWindow, text=f"Password: {blank}")
	passwordLabel.grid(row=2, columnspan=2)

	show_password = tk.BooleanVar()
	show_password_checkbox = tk.Checkbutton(passManInfoWindow, text="Show Password", variable=show_password, command=lambda: (toggle_show_password(passwordLabel)))
	show_password_checkbox.grid(row=3, columnspan=2)

	closeButton = tk.Button(passManInfoWindow, text="Close", command=passManInfoWindow.destroy)
	closeButton.grid(row=4, column=0)
	
	#button calls a function which takes user to another window to edit the selected accounts info
	editAccInfoBtn = tk.Button(passManInfoWindow, text="Edit Account Info", command=lambda: [editAccInfo(usernameEmail, passkey, platform, password, passmanEmail, passmanPassword, passmanWindow, passManInfoWindow)])
	editAccInfoBtn.grid(row=4, column=1)
	
#this function lets user edit their account info, like the Password, Username/Email, and Platform
def editAccInfo(email, passkey, platform, password, passmanEmail, passmanPassword, passmanWindow, passManInfoWindow):
	
	def toggle_show_password(passwordEntry):
		if show_password.get():
			passwordEntry.config(show="")
		else:
			passwordEntry.config(show="*")

	editAccInfoWin = tk.Toplevel()

	platformLabel = tk.Label(editAccInfoWin, text="Platform:")
	platformLabel.grid(row=0, column=0)
	platformEntry = tk.Entry(editAccInfoWin)
	platformEntry.grid(row=0, column=1)

	emailLabel = tk.Label(editAccInfoWin, text="Email/Username:")
	emailLabel.grid(row=1, column=0)
	emailEntry = tk.Entry(editAccInfoWin)
	emailEntry.grid(row=1, column=1)

	passwordLabel = tk.Label(editAccInfoWin, text="Password:")
	passwordLabel.grid(row=2, column=0)
	passwordEntry = tk.Entry(editAccInfoWin, show='*')
	passwordEntry.grid(row=2, column=1)

	show_password = tk.BooleanVar()
	show_password_checkbox = tk.Checkbutton(editAccInfoWin, text="Show Password", variable=show_password, command=lambda: (toggle_show_password(passwordEntry)))
	show_password_checkbox.grid(row=3, column=1)

	cancelButton = tk.Button(editAccInfoWin, text="Cancel", command=editAccInfoWin.destroy)
	cancelButton.grid(row=4, column=0)

	addAccountBtn = tk.Button(editAccInfoWin, text="Edit Info", command=lambda : [ commitEdit(email, passkey, platform, password, emailEntry.get(), platformEntry.get(), passwordEntry.get(), editAccInfoWin, passmanEmail, passmanPassword, passmanWindow, passManInfoWindow) if messagebox.askyesno('Confirming Changes', 'Are you sure you want to commit the changes?') else None])
	addAccountBtn.grid(row=4, column=1)
	
#when the changes are confirmed they get commited by this function
def commitEdit(oldEmail, passkey, oldPlatform, oldPassword, newEmail, newPlatform, newPassword, editAccInfoWin, passmanEmail, passmanPassword, passmanWindow, passManInfoWindow):
	with open(f'{filePath}-{passmanEmail}.json', 'r') as file:
		data = json.load(file)

	for entry in data:
		if entry['Username/Email'] == oldEmail and entry['Platform'] == oldPlatform and entry['Password'] == pm.returnEncryptedPassword(oldPassword, passkey):
			entry['Username/Email'] = newEmail or oldEmail
			entry['Platform'] = newPlatform or oldPlatform
			entry['Password'] = pm.returnEncryptedPassword(newPassword, passkey) or pm.returnEncryptedPassword(oldPassword, passkey)

	with open(f'{filePath}-{passmanEmail}.json', 'w') as file:
		json.dump(data, file, indent=4)

	if oldPlatform == 'Passman':
		fileName = newEmail or oldEmail
		os.rename(f'{filePath}-{oldEmail}.json', f'{filePath}-{fileName}.json')
	else:
		None

	if oldPlatform == 'Passman':
		passmanPassword = newPassword or oldPassword
		passmanEmail = newEmail or oldEmail
	else:
		None

	passManInfoWindow.destroy()
	editAccInfoWin.destroy()
	passmanWindow.destroy()
	credentialsCheck(passmanEmail, passmanPassword, passkey, "Passman")

#the main window where you can see your added accounts' information
def passmanWindow(email, password, passkey, platform):
	mainmenu.withdraw()
	passmanWindow = tk.Toplevel()
	
	num = passManButtonCreator(passmanWindow, email, passkey, password, passmanWindow)

	addAccBtn = tk.Button(passmanWindow, text="Add Account", command=lambda : addAccount(email, password, passkey, platform, passmanWindow))
	addAccBtn.grid(column=0, row=num)

	exitButton1 = tk.Button(passmanWindow, text="Exit", command=lambda: [mainmenu.deiconify(), passmanWindow.destroy()])
	exitButton1.grid(column=1, row=num)

	delAccBtn = tk.Button(passmanWindow, text="Delete Account", command=lambda : deleteAccount(email, passkey, password, platform, passmanWindow))
	delAccBtn.grid(column=2, row=num)

#this function is to add accounts other then Passman
def addAccount(email, password, passkey, platform, passmanWindow):
	
	def toggle_show_password(passwordEntry):
		if show_password.get():
			passwordEntry.config(show="")
		else:
			passwordEntry.config(show="*")

	addAccWindow = tk.Toplevel()

	platformLabel = tk.Label(addAccWindow, text="Platform:")
	platformLabel.grid(row=0, column=0)
	platformEntry = tk.Entry(addAccWindow)
	platformEntry.grid(row=0, column=1)

	emailLabel = tk.Label(addAccWindow, text="Email/Username:")
	emailLabel.grid(row=1, column=0)
	emailEntry = tk.Entry(addAccWindow)
	emailEntry.grid(row=1, column=1)

	passwordLabel = tk.Label(addAccWindow, text="Password:")
	passwordLabel.grid(row=2, column=0)
	passwordEntry = tk.Entry(addAccWindow, show='*')
	passwordEntry.grid(row=2, column=1)

	show_password = tk.BooleanVar()
	show_password_checkbox = tk.Checkbutton(addAccWindow, text="Show Password", variable=show_password, command=lambda: (toggle_show_password(passwordEntry)))
	show_password_checkbox.grid(row=3, column=1)

	cancelButton = tk.Button(addAccWindow, text="Cancel", command=addAccWindow.destroy)
	cancelButton.grid(row=4, column=0)

	addAccountBtn = tk.Button(addAccWindow, text="Add Account", command=lambda : addingAccount(platformEntry.get(), emailEntry.get(), passwordEntry.get(), addAccWindow, email, password, passkey, platform, passmanWindow))
	addAccountBtn.grid(row=4, column=1)

#this function is called to add the account to the Passman.json
def addingAccount(newPlatform, newEmail, newPassword, addAccWindow, passmanEmail, passmanPassword, passkey, passmanPlatform, passmanWindow):
	platform = newPlatform
	email = newEmail
	password = newPassword

	matched = False
	
	with open(f'{filePath}-{passmanEmail}.json', 'r') as file:
		data = json.load(file)
		for entry in data:
			if entry['Platform'] == platform and entry['Username/Email'] == email and pm.decryptPassword(entry['Username/Email'], entry['Platform']) == password:
				matched = True

	print(matched)


	if matched:
		messagebox.showerror("Error", "Account Already Exists!")
	else:
		confirmation = messagebox.askyesno("Confirmation", "Are you sure you want to add this account to Passman?")
		if confirmation:
			pm.encryptPassword(password, email, passkey, platform, passmanEmail)
			passmanWindow.destroy()
			credentialsCheck(passmanEmail, passmanPassword, passkey, passmanPlatform)
			addAccWindow.destroy()

#account deletion window that shows your accounts that can be deleted
def deleteAccount(email, passkey, password, platform, passmanWindow):
	delAccWindow = tk.Toplevel()

	delAccBtnCreator(delAccWindow, email, passkey, password, platform, passmanWindow, delAccWindow)

	cancelButton = tk.Button(delAccWindow, text="Cancel", command=delAccWindow.destroy)
	cancelButton.grid()

#if an account selected for deletion then this function us called. it asks for confirmatin then deletes the selected account.
def deletingAccount(target_entry, json_data, passmanEmail, passmanPassword, passmanPlatform, passkey, passmanWindow, delAccWindow):

	platform = target_entry['Platform']

	if platform == 'Passman':
		deleting_passman(delAccWindow, passmanWindow, passmanEmail)

	else:	
		confirmation = messagebox.askokcancel("Confirmation", "Are you sure you want to delete this account")

		if confirmation:

			json_data[:] = [entry for entry in json_data if not all(entry[key] == value for key, value in target_entry.items())]

			with open(f'{filePath}-{passmanEmail}.json', 'w') as file:
				json.dump(json_data, file, indent=4)

			delAccWindow.destroy()

			passmanWindow.destroy()

			credentialsCheck(passmanEmail, passmanPassword, passkey, passmanPlatform)

def deleting_passman(delAccWindow,passmanWindow, passmanEmail):
	confirmation = messagebox.askyesno("Deleting Passman!", "Warning! You're about to Delete your Passman account! Do you wish to continue?")

	if confirmation:
		delAccWindow.destroy()
		passmanWindow.destroy()
		deletionPath = f'{filePath}-{passmanEmail}.json'
		os.remove(deletionPath)
		mainmenu.deiconify()

#asks for permission, if confirmed calls the password recovery function in Passman.py
def passwordRecovery():

	mainmenu.withdraw()

	passwordRecoveryWindow = tk.Toplevel()

	passwordRecoveryLabel = tk.Label(passwordRecoveryWindow, text="Passman Password Recovery!")
	passwordRecoveryLabel.grid(row=0, column=0, columnspan=2)

	warningLabel = tk.Label(passwordRecoveryWindow, text="Warning! your password will be sent in plain text to your Passman Email! Recovery email could take up to 5 minutes, patience is virtue!", fg="red", wraplength=150)
	warningLabel.grid(row=1, column=0, columnspan=2, rowspan=2)

	usernameLabel = tk.Label(passwordRecoveryWindow, text="Passman Username/Email")
	usernameLabel.grid(row=3, column=0)
	usernameEntry = tk.Entry(passwordRecoveryWindow)
	usernameEntry.grid(row=3, column=1)

	recoveryEmailLabel = tk.Label(passwordRecoveryWindow, text="Recovery Email")
	recoveryEmailLabel.grid(row=4, column=0)
	recoveryEmailEntry = tk.Entry(passwordRecoveryWindow)
	recoveryEmailEntry.grid(row=4, column=1)

	passkeyLabel = tk.Label(passwordRecoveryWindow, text="Passkey")
	passkeyLabel.grid(row=5, column=0)
	passkey1Entry = tk.Entry(passwordRecoveryWindow)
	passkey1Entry.grid(row=5, column=1)

	cancelbutton = tk.Button(passwordRecoveryWindow, text="Cancel", command= lambda: [passwordRecoveryWindow.destroy(), mainmenu.deiconify()])
	cancelbutton.grid(row=6, column=0)

	doneButton = tk.Button(passwordRecoveryWindow, text="Done", command= lambda: error_handling(passkey1Entry.get(), recoveryEmailEntry.get(), usernameEntry.get()))
	doneButton.grid(row=6, column=1)

	def error_handling(passkey, email, username):
		try:
			if passkey == "" or email == "" or username == "":
				messagebox.showerror("Recovery Email not sent!", "one or more fields were empty!")
			else:
				passwordRecoveryWindow.destroy()
				mainmenu.deiconify()
				pm.passwordRecovery(passkey, email, username)
		except ValueError:
			messagebox.showerror("Value Error!", "Recovery Message not sent!")


mainmenu_label = tk.Label(mainmenu, text="Passman Login")
mainmenu_label.grid(row=0, column=0, columnspan=2)

emailLabel = tk.Label(mainmenu, text="Email:")
emailLabel.grid(row=1, column=0)
emailEntry = tk.Entry(mainmenu)
emailEntry.grid(row=1, column=1)

passkeyLabel = tk.Label(mainmenu, text="Passkey:")
passkeyLabel.grid(row=2, column=0)
passkeyEntry = tk.Entry(mainmenu)
passkeyEntry.grid(row=2, column=1)

passwordLabel = tk.Label(mainmenu, text="Password:")
passwordLabel.grid(row=3, column=0)
passwordEntry = tk.Entry(mainmenu, show="*")
passwordEntry.grid(row=3, column=1)

show_password = tk.BooleanVar()
show_password_checkbox = tk.Checkbutton(mainmenu, text="Show Password", variable=show_password, command=lambda: (toggle_show_password(passwordEntry)))
show_password_checkbox.grid(row=4, column=1)

loginButton = tk.Button(mainmenu, text="login", width=16, bg="#00ff00", activebackground="#008f00", command= lambda: [dirCheck(emailEntry.get(), passwordEntry.get(), passkeyEntry.get(), "Passman", ), passwordEntry.delete(0, tk.END), emailEntry.delete(0, tk.END), passkeyEntry.delete(0, tk.END)])
loginButton.grid(row=5, column=1)

exitButton = tk.Button(mainmenu, text="Exit", width=12, bg="#ff0000", activebackground="#a80000", command=mainmenu.destroy)
exitButton.grid(row=5, column=0)

#the "Forgot Password?" button
forgotPasswordButton = tk.Button(mainmenu, text="Forgot Password? :(", command=passwordRecovery, fg="blue")
forgotPasswordButton.grid(row=6, columnspan=2)

mainmenu.mainloop()
