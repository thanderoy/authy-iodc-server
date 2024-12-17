from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.common import Request


class AuthyOAuth2Validator(OAuth2Validator):

    def get_additional_claims(self, request):
        return {
            "first_name": request.user.first_name,
            "last_name": request.user.last_name,
            "email": request.user.email,
        }

    def get_userinfo_claims(self, request):
        initial_data = super().get_userinfo_claims(request)
        initial_data.update(self.get_additional_claims(request))
        return initial_data

    def validate_silent_login(self, request) -> None:
        pass

    def introspect_token(self, token: str, token_type_hint: str, request: Request, *args, **kwargs) -> dict[str, int | str | list[str]] | None:     # noqa: E501
        pass

    def validate_silent_authorization(self, request) -> None:
        pass
