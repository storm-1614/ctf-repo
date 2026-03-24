/*
 * =====================================================================================
 *
 *       Filename:  main.cpp
 *
 *    Description: int overflow
 *
 *        Version:  1.0
 *        Created:  03/24/2026 12:28:23 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  storm-1614
 *   Organization:
 *
 * =====================================================================================
 */
#include <climits>
#include <iostream>

int main()
{
    size_t n = INT_MIN;
    std::cout << (int)n << std::endl;
    std::cout << (unsigned int)n << std::endl;
    return 0;
}
