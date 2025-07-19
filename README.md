Secure_config is a library that helps create securized configuration files for your apps. 
This program will prevent your program to run configutation files created or modified by 
anyone except the program itself. 

How it works:
> You generate an inactive configuration file and activation key that you deliver with the program (or you can 
    set a user-picked password during the generation to not remind the user of the hated Windows keys). 
> In the moment the user will activate the key with the activate() function, the program will automatically 
make a fingerprint on your system as well as a timestamp. 
> Based on the parameters you set when you generate the file, the program will disable or corrupt 
the configuration file if one or both of of the security features is changed. 
> Therefore the file will be impossible to edit from a different program, and/or run with the intended program
on a different computer. You can change these behaviours in the args parameter within the generate() function
(Note: This will not be available to the user of the program by a premade function.)

Usage:

You need to import secure_config to use the lib. You don't need the Test program folder. That's just a little demo which you can erase.


generate -- generates the secure file and activation key to be delivered with the program (This is not part of the program itself, but rather a tool to make the file to be delivered with the program. You can aslo use it with a setup script or however you want for that matter. I'm not telling you what you can't do!)

generate(path,key_length, password <to be embeded in the program>,args<# args timestamp T corrupt / t disable; system fingerprint F corrupt / f disable; p pass errors if arg missing>,
       print_data=True<Hides the library's printing useful if you use it in a program>, key<uses any string you put there as the key (optional)>)

activate(path,password,auth_key) if file inactive or disabled

read_file(path,password) returns the content of the file(ie. what YOU store inside it)

write_file(path,password,content) allows you to write [content: anything] to the file just like pickle

def check_status(path,password) returns the status of the file as str: "inactive","disabled","active",or "corrupted".

Security:

This lib provides a level of security, but like anything made by humans, it is not foolproof. This program will provide protection against an unauthorized user without great IT skills, and might even resist against a more experienced hacker, but a determined and experienced attacker will probably find a way to beat it. 

> The program uses pickle which can be exploited.

> The timestamp of the file, if read before copying the file, can be changed with easily available tools (if the attacker copies the file before reading the timestamp, this won't work).

> The content is encrypted, but for certain purposes, the attacker might just need to restore an older file without tampering it's content. 

> If the encryptopn password is not securely stored, I don't even need to mention. (That wouldn't acutually be my fault though.)

> Changes to hardware might also change the fingerprint and thus trigger an error.

This library is not intended for military grade security. It is intended to provide a secure .config file, and protect against unauthorized tampering of a program's files, and for the most cases it will do it's job. This is not designed to encrypt your most sensitive data, and it's core security features can lead to LOSS OF THE STORED DATA. 




