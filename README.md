# Trivial SASL provider #

Use this to add a trivial SASL provider to your Postfix.

Take this sourcefile, modify it so you have a less insecure password, and then just run it on your Postfix server.

Follow the regular postfix tricks to configure it, so you may want put something like this in your main.cf:

```
smtpd_sasl_auth_enable=yes
smtpd_sasl_type=dovecot
smtpd_sasl_path=private/auth
smtpd_sasl_security_options=noanonymous
smtpd_sasl_local_domain=$myhostname
```

Then you can use swaks to try it out:

```
$ swaks \
  --helo my.host.name \
  --from sender@my.domain \
  --to recipient@my.domain \
  --server 1.2.3.4:25 \
  --auth PLAIN \
  --auth-user test \
  --auth-password foobar \
  -tls
```

and all should be fine. If it doesnʼt work, increase the log level in
the source file and/or look at the Postfix logs.
