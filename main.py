#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re

form="""
<form method="post">
    <table>
    <tr>
        <td class="label">
            Username:
        </td>
        <td>
            <input type="text" name="username" value="%(username)s">%(user_error)s
        </td>
    </tr>
    <tr>
        <td class="label">
            Password:
        </td>
        <td>
        <input type="password" name="password" value="">%(password_error)s
        </td>
    </tr>
    <tr>
        <td class="label">
            Confirm Password:
        </td>
        <td>
            <input type="password" name="confirmp" value="">%(confirmp_error)s
        </td>
    </tr>
    <tr>
        <td class="label">
            Email(Optional):
        </td>
        <td>
            <input type="text" name="email" value="%(email)s">%(email_error)s
        </td>
    </tr>
    </table>
    <input type="submit">
</form>
"""
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class MainHandler(webapp2.RequestHandler):
    def write_form(self, user_error="", password_error="", confirmp_error="", email_error="", username="",
                    password="", confirmp="", email=""):
        self.response.write(form % {"user_error":user_error,
                                    "password_error":password_error,
                                    "confirmp_error":confirmp_error,
                                    "email_error":email_error,
                                        "username": username,
                                        "password":password,
                                        "confirmp":confirmp,
                                        "email":email})
    def get(self):
        self.write_form()
    def post(self):
        has_error = False
        username = self.request.get(cgi.escape("username"))
        password = self.request.get(cgi.escape("password"))
        confirmp = self.request.get(cgi.escape("confirmp"))
        user_error = ""
        password_error = ""
        confirmp_error=""
        email_error=""
        email = self.request.get(cgi.escape("email"))



        if not valid_username(username):
            user_error = "That's not a valid username."
            has_error = True

        if not valid_password(password):
            password_error = "That wasn't a valid password."
            has_error = True

        elif password != confirmp:
            confirmp_error = "Your passwords didn't match."
            has_error = True

        if not valid_email(email):
            email_error = "That's not a valid email."
            has_error = True

        if has_error:
            self.write_form(user_error, password_error, confirmp_error, email_error, username,
                            password, confirmp, email)
        else:
            self.redirect('/welcome?username=' + username)

class HomeHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write("You Logged in, Good Job!")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', HomeHandler)
], debug=True)
