# HTTPd

Plugin for the Indigo Home Automation system.

Runs one or more HTTP server(s) inside Indigo.

Create an HTTP Server device for each port you want served.  Each service instance (Indigo device) has it's own port, username/password, etc.  If you want to enable SSL for a port, see the Wiki for instructions.

You'll need to set up port forwarding on your router to the specified port.  Only ports > 1024 can be used.

Example URL to activate the plugin:

    http://username:password@my.domain.org:5566/setvar?foo=bar&zig=zag
    
The first "action" the plugin supports is "/setvar". This will set the specified variables to the values given. For protection, the variables have "httpd_" prepended to the names provided. In this case, the Indigo variable "httpd_foo" would be set to "bar", and the Indigo variable "httpd_zig" would be set to "zag". If they don't exist, the variables are created in an "HTTPd" variable folder. "/setvar" is available with either GET or POST http methods.

The next action is "/webhook". The syntax is similar:

    http://username:password@my.domain.org:5566/webhook?name=test

In this case, the plugin will do a broadcastToSubscribers call:

    indigo.server.broadcastToSubscribers(u"httpd_webhook", broadcastDict)

and the contents of broadcastDict would be:

	{
    'request': {
     	...<the Headers from the HTTP POST request>...
    }, 
    'payload': {
     	... <the POST payload>...
    }, 
    'vars': {
        'name': 'test', 
    }
}

For more details on the URL path and payload options see the Wiki.

