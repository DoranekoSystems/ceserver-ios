/*
 * symbols.h
 *
 *  Created on: Aug 7, 2013
 *      Author: eric
 */

#ifndef SYMBOLS_H_
#define SYMBOLS_H_

#include "api.h"

unsigned long long GetModuleSize(char *filename, uint32_t fileoffset,
                                 unsigned long long defaultsize);
#endif /* SYMBOLS_H_ */