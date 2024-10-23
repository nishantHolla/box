#ifndef B_TEST_H_
#define B_TEST_H_

#define TEST_SEPARATOR "-----------------------------------------------------\n"

#define TEST_CASE(x) printf("%2d: Testing   %-30s: ", (++test_case_length), x)
#define TEST_CASE_PASSED printf("Passed\n"); test_case_passed++
#define TEST_CASE_FAILED(fmt, ...) printf("Failed "); printf(fmt, ##__VA_ARGS__); printf("\n")
#define TEST_RESULT printf("%s", TEST_SEPARATOR); printf("Result: Passed %d tests out of %d\n", test_case_passed, test_case_length)

#endif // !B_TEST_H_
