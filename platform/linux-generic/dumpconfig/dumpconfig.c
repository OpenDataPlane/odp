/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#include <stdio.h>
#include <stdlib.h>
#include <odp_libconfig_config.h>

int main(void)
{
	unsigned int i;
	const char *filename;
	FILE *f;
	int c;

	printf("# Builtin platform config\n\n");
	for (i = 0; i < sizeof(config_builtin); i++)
		printf("%c", config_builtin[i]);

	filename = getenv("ODP_CONFIG_FILE");
	if (filename == NULL)
		return 0;

	printf("# Overridden section with ODP_CONFIG_FILE=%s\n\n", filename);

	f = fopen(filename, "r");
	if (f == NULL)  {
		fprintf(stderr, "Error: open file %s\n", filename);
		return -1;
	}

	while ((c = fgetc(f)) != EOF)
		putchar(c);

	fclose(f);
	return 0;
}
