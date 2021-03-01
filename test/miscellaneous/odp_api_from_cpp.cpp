#include <iostream>
#include <odp_api.h>
#include <odp/helper/odph_api.h>

int main(int argc ODP_UNUSED, const char *argv[] ODP_UNUSED)
{
	odp_instance_t inst;

	odp_init_global(&inst, NULL, NULL);
	odp_init_local(inst, ODP_THREAD_WORKER);

	std::cout << "\tODP API version: " << odp_version_api_str() << std::endl;
	std::cout << "\tODP implementation version: " << odp_version_impl_str() << std::endl;

	odp_term_local();
	odp_term_global(inst);

	return 0;
}
