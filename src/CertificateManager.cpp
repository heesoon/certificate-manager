#include <iostream>
#include <openssl/engine.h>

#if 0
static const char *engine_id = "silly";
static const char *engine_name = "A silly engine for demonstration purposes";

static int bind(ENGINE *e, const char *id)
{
  int ret = 0;

  if (!ENGINE_set_id(e, engine_id)) {
    fprintf(stderr, "ENGINE_set_id failed\n");
    goto end;
  }
  if (!ENGINE_set_name(e, engine_name)) {
    printf("ENGINE_set_name failed\n");
    goto end;
  }

  ret = 1;
 end:
  return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()

#endif

int main()
{
	//ENGINE_load_openssl();
	//ENGINE_load_dynamic();
	ENGINE_load_builtin_engines();
	//ENGINE *e = ENGINE_get_first();
	ENGINE_register_all_complete();
	ENGINE *e = ENGINE_get_default_RSA();
	if(e == NULL)
	{
		std::cout << "engine null" << std::endl;
		return 0;
	}

	std::cout << "first engine : " << ENGINE_get_name(e) << std::endl;
	return 0;
}