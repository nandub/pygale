/*
** $Id: opensslc.c,v 1.3 2006/07/12 07:05:25 jtr Exp $
*/

#include <Python.h>
#include <stdio.h>
#include <openssl/err.h>

#include "opensslc.h"

static PyObject* OpenSSLErr;

extern void init_randc(void);
extern void init_bnc(void);
extern void init_rsac(void);
extern void init_evpc(void);

void
generate_error(char* message)
{
	unsigned long openssl_error;
	char error_string[1024];

	if (message == NULL)
	{
		message = DEFAULT_ERROR_MESSAGE;
	}

	openssl_error = ERR_get_error();
	ERR_error_string(openssl_error, error_string);
	PyErr_Format(OpenSSLErr, "%s: %s", message, error_string);
}

static PyMethodDef opensslcMethods[] = 
{
	{ NULL, NULL }
};

void
initopensslc()
{
	PyObject *m, *d;
	
	m = Py_InitModule("opensslc", opensslcMethods);
	d = PyModule_GetDict(m);

	OpenSSLErr = PyErr_NewException("opennsl.OpensslErr", NULL, NULL);
	if (OpenSSLErr == NULL)
	{
		fprintf(stderr, "Error creating OpenSSLErr\n");
	}
	init_randc();
	init_bnc();
	init_rsac();
	init_evpc();
}
