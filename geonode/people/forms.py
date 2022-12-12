#########################################################################
#
# Copyright (C) 2016 OSGeo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################

import taggit
import hashlib
from django.utils.crypto import pbkdf2
import base64

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.utils.translation import ugettext as _

from datetime import datetime
import requests
from allauth.account.forms import SignupForm, LoginForm, PasswordField
from .utils import filter_users_by_iin



import logging


from captcha.fields import ReCaptchaField

# Ported in from django-registration
attrs_dict = {'class': 'required'}


class AllauthReCaptchaSignupForm(forms.Form):

    captcha = ReCaptchaField()

    def signup(self, request, user):
        """ Required, or else it thorws deprecation warnings """
        pass


class ProfileCreationForm(UserCreationForm):

    class Meta:
        model = get_user_model()
        fields = ("username",)

    def clean_username(self):
        # Since User.username is unique, this check is redundant,
        # but it sets a nicer error message than the ORM. See #13147.
        username = self.cleaned_data["username"]
        try:
            get_user_model().objects.get(username=username)
        except get_user_model().DoesNotExist:
            return username
        raise forms.ValidationError(
            self.error_messages['duplicate_username'],
            code='duplicate_username',
        )


class ProfileChangeForm(UserChangeForm):

    class Meta:
        model = get_user_model()
        fields = '__all__'


class ForgotUsernameForm(forms.Form):
    email = forms.EmailField(widget=forms.TextInput(attrs=dict(attrs_dict,
                                                               maxlength=75)),
                             label=_('Email Address'))


class ProfileForm(forms.ModelForm):
    keywords = taggit.forms.TagField(
        label=_("Keywords"),
        required=False,
        help_text=_("A space or comma-separated list of keywords"))

    class Meta:
        model = get_user_model()
        exclude = (
            'user',
            'password',
            'last_login',
            'groups',
            'user_permissions',
            'username',
            'is_staff',
            'is_superuser',
            'is_active',
            'date_joined',
            'iin'
        )

class CustomSignupForm(SignupForm):
    def __init__(self, *args, **kwargs):
        super(CustomSignupForm, self).__init__(*args, **kwargs)
        # del self.fields["username"]

    sign = forms.CharField(widget=forms.HiddenInput())

    def clean(self):
        cleaned_data = super(CustomSignupForm, self).clean()
        
        value = cleaned_data.get("sign")

        r = requests.post('http://ncanode:14579', json={'version': '1.0', 'method': 'XML.verify', 'params': {'xml': value}})

        result = r.json()['result']
        cert_finish_date = datetime.strptime(result['cert']['notAfter'], '%Y-%m-%d %H:%M:%S')
        iin = result['cert']['subject']['iin']
        common_name  = result['cert']['subject']['commonName'].split()
        first_name = common_name[1]
        last_name = common_name[0]

        # iin_hash = hashlib.sha1(force_bytes(iin)).hexdigest()
        iin_hash_base64 = pbkdf2(iin, '1234', 20000, digest=hashlib.sha256)
        iin_hash = base64.b64encode(iin_hash_base64).decode('ascii').strip()

        if filter_users_by_iin(iin_hash).exists():
            raise forms.ValidationError(_('IIN already taken'))
        if not result['valid'] or not result['cert']['valid']:
            raise forms.ValidationError(_('Sign not valid'))
        if datetime.today() > cert_finish_date:
            raise forms. ValidationError(_('Sign date expired'))
        
        self.cleaned_data['iin'] = iin_hash
        self.cleaned_data['first_name'] = first_name
        self.cleaned_data['last_name'] = last_name

        return self.cleaned_data

class CustomLoginForm(LoginForm):
    def __init__(self, *args, **kwargs):
        super(CustomLoginForm, self).__init__(*args, **kwargs)
        iin_widget = forms.TextInput(
            attrs={"placeholder": _("IIN")}
        )
        iin_field = forms.CharField(
            label=_("IIN"),
            widget=iin_widget,
            required=False
        )
        self.fields["iin"] = iin_field
        self.fields["password"] = PasswordField(label=_("Password"), autocomplete="current-password", required=False)
        del self.fields["login"]

    def user_credentials(self):
        # credentials = super(CustomLoginForm, self).user_credentials()
        credentials = {}
        credentials["iin"] = self.cleaned_data["iin"]
        credentials["password"] = self.cleaned_data["password"]
        credentials["sign"] = self.cleaned_data["sign"]
        return credentials

    def clean(self):
        if self.cleaned_data["iin"]:
            iin_hash_base64 = pbkdf2(self.cleaned_data["iin"], '1234', 20000, digest=hashlib.sha256)
            iin_hash = base64.b64encode(iin_hash_base64).decode('ascii').strip()
            self.cleaned_data["iin"] = iin_hash
        if self._errors:
            return
        credentials = self.user_credentials()
        from allauth.account.adapter import get_adapter
        user = get_adapter(self.request).authenticate(self.request, **credentials)
        if user:
            self.user = user
        else:
            raise forms.ValidationError(
                _("User not exists")
            )
        return self.cleaned_data

    sign = forms.CharField(widget=forms.HiddenInput(), required=False)