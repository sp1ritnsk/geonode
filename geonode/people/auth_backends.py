from datetime import datetime
from threading import local
from django import forms

from django.contrib.auth.backends import ModelBackend
import requests

from allauth.utils import get_user_model
from .utils import filter_users_by_iin
from django.utils.translation import gettext_lazy as _

_stash = local()


class SignAuthenticationBackend(ModelBackend):
    def authenticate(self, request, **credentials):
        sign = credentials.get("sign")

        User = get_user_model()

        if sign is None:
            return None
        try:
            r = requests.post('http://ncanode:14579', json={'version': '1.0', 'method': 'XML.verify', 'params': {'xml': sign}})
            rjson = r.json()

            if not (rjson['status'] == 0):
                return None

            result = rjson['result']
            cert_finish_date = datetime.strptime(result['cert']['notAfter'], '%Y-%m-%d %H:%M:%S')
            iin = result['cert']['subject']['iin']

            if not result['valid'] or not result['cert']['valid']:
                raise forms.ValidationError(_('Sign not valid'))
            if datetime.today() > cert_finish_date:
                raise forms. ValidationError(_('Sign date expired'))

            user = filter_users_by_iin(iin).get()

            ret = self.user_can_authenticate(user)
            if not ret:
                self._stash_user(user)

            return user
        except User.DoesNotExist:
            return None

    @classmethod
    def _stash_user(cls, user):
        """Now, be aware, the following is quite ugly, let me explain:

        Even if the user credentials match, the authentication can fail because
        Django's default ModelBackend calls user_can_authenticate(), which
        checks `is_active`. Now, earlier versions of allauth did not do this
        and simply returned the user as authenticated, even in case of
        `is_active=False`. For allauth scope, this does not pose a problem, as
        these users are properly redirected to an account inactive page.

        This does pose a problem when the allauth backend is used in a
        different context where allauth is not responsible for the login. Then,
        by not checking on `user_can_authenticate()` users will allow to become
        authenticated whereas according to Django logic this should not be
        allowed.

        In order to preserve the allauth behavior while respecting Django's
        logic, we stash a user for which the password check succeeded but
        `user_can_authenticate()` failed. In the allauth authentication logic,
        we can then unstash this user and proceed pointing the user to the
        account inactive page.
        """
        global _stash
        ret = getattr(_stash, "user", None)
        _stash.user = user
        return ret

    @classmethod
    def unstash_authenticated_user(cls):
        return cls._stash_user(None)

class IinAuthenticationBackend(ModelBackend):
    def authenticate(self, request, **credentials):
        iin = credentials.get("iin")
        password = credentials.get("password")

        User = get_user_model()

        if iin is None or password is None:
            return None
        try:
            user = filter_users_by_iin(iin).get()
            ret = user.check_password(password)
            if ret:
                ret = self.user_can_authenticate(user)
                if not ret:
                    self._stash_user(user)

            if ret:
                return user
        except User.DoesNotExist:
            return None
    
    @classmethod
    def _stash_user(cls, user):
        """Now, be aware, the following is quite ugly, let me explain:

        Even if the user credentials match, the authentication can fail because
        Django's default ModelBackend calls user_can_authenticate(), which
        checks `is_active`. Now, earlier versions of allauth did not do this
        and simply returned the user as authenticated, even in case of
        `is_active=False`. For allauth scope, this does not pose a problem, as
        these users are properly redirected to an account inactive page.

        This does pose a problem when the allauth backend is used in a
        different context where allauth is not responsible for the login. Then,
        by not checking on `user_can_authenticate()` users will allow to become
        authenticated whereas according to Django logic this should not be
        allowed.

        In order to preserve the allauth behavior while respecting Django's
        logic, we stash a user for which the password check succeeded but
        `user_can_authenticate()` failed. In the allauth authentication logic,
        we can then unstash this user and proceed pointing the user to the
        account inactive page.
        """
        global _stash
        ret = getattr(_stash, "user", None)
        _stash.user = user
        return ret
        
    @classmethod
    def unstash_authenticated_user(cls):
        return cls._stash_user(None)