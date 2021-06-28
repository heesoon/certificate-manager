#include <iostream>
#include "opensslEngineWrapper.hpp"

static ENGINE *try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e) {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", "/home/hskim/github/certificate-manager/build/src/libopensslEngine.so", 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}

int main()
{
#if 0	
    //ENGINE_load_dynamic();
    ENGINE *eng = ENGINE_by_id("hsm");

    ENGINE_ctrl_cmd_string(eng, "SO_PATH", "/home/hskim/github/certificate-manager/build/src/libopensslEngine.so", 0);
    ENGINE_ctrl_cmd_string(eng, "ID", "hsm", 0);
    ENGINE_ctrl_cmd_string(eng, "LOAD", NULL, 0);
    //ENGINE_ctrl_cmd_string(eng, "CMD_FOO", "some input data", 0);

	//ENGINE_load_dynamic();
	 printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
    if(NULL == eng) {
        printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
        abort(); // failed
    }

#endif

	const char *engine = "hsm";
	ENGINE *e = NULL;

	if ((e = ENGINE_by_id(engine)) == NULL
		&& (e = try_load_engine(engine)) == NULL) {
		//BIO_printf(bio_err, "invalid engine \"%s\"\n", engine);
		//ERR_print_errors(bio_err);
		printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return NULL;
	}
	std::cout << "Success " << std::endl;
	return 1;
}