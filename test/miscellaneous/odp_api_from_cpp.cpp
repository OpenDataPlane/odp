#include <stdlib.h>
#include <iostream>
#include <odp_api.h>
#include <odp/helper/odph_api.h>

int main(int argc ODP_UNUSED, const char *argv[] ODP_UNUSED)
{
	odp_instance_t inst;

	if (odp_init_global(&inst, NULL, NULL))
		exit(EXIT_FAILURE);

	if (odp_init_local(inst, ODP_THREAD_WORKER))
		exit(EXIT_FAILURE);

	std::cout << "\tODP API version: " << odp_version_api_str() << std::endl;
	std::cout << "\tODP implementation version: " << odp_version_impl_str() << std::endl;

	if (odp_term_local())
		exit(EXIT_FAILURE);

	if (odp_term_global(inst))
		exit(EXIT_FAILURE);

	return 0;
}
