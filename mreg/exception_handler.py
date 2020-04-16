from rest_framework.views import exception_handler

def custom_exception_handler(exc, context):
	# Call REST framework's default exception handler first,
	# to get the standard error response.
	response = exception_handler(exc, context)

	if response is not None and response.status_code == 400 \
		and 'non_field_errors' in response.data \
		and len(response.data['non_field_errors'])>0 \
		and response.data['non_field_errors'][0] == "Unable to log in with provided credentials.":
		response.status_code = 401

	return response