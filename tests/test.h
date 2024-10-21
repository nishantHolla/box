#ifndef B_TEST_H_
#define B_TEST_H_

#define TEST_CASE(x) printf("%2d: Testing %s\t\t: ", (++test_case_length), x)
#define TEST_CASE_PASSED printf("Passed\n"); test_case_passed++
#define TEST_CASE_FAILED(fmt, ...) printf("Failed "); printf(fmt, ##__VA_ARGS__); printf("\n")

#endif // !B_TEST_H_
