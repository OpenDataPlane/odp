#include <iostream>
#include <odp_api.h>
#include <odp/helper/odph_api.h>

int main(int argc ODP_UNUSED, const char *argv[] ODP_UNUSED)
{
	std::cout << "\tODP API version: " << odp_version_api_str() << std::endl;
	std::cout << "\tODP implementation version: " << odp_version_impl_str() << std::endl;

	return 0;
}
