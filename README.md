dnschan
=======

This is a fully-functional trojan that runs over DNS. Its main goal is
to provide a "low and slow" foothold on the target network, after which
its upload functionality can be used to deliver a more advanced remote
access trojan, e.g. meterpreter.

Features include:
- support for multiple connections
- file upload from local to remote
- fetch a file from a URL and save it on the remote system
- spawn a new background process on the remote system
- re-transmission of dropped packets for file uploads
