#include <stdlib.h>
#include <math.h>

// Function to compare two integers for qsort
int compare(const void *a, const void *b) {
    return (*(double *)a - *(double *)b);
}

// Function to calculate the mean
double calculateMean(double arr[], int size) {
    double sum = 0.0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum / size;
}

// Function to calculate the median
double calculateMedian(double arr[], int size) {
    qsort(arr, size, sizeof(double), compare);
    if (size % 2 != 0) {
        return arr[size / 2];
    } else {
        return (arr[(size - 1) / 2] + arr[size / 2]) / 2.0;
    }
}

// Function to calculate the standard deviation
double calculateStandardDeviation(double arr[], int size, double mean) {
    double sum = 0.0;
    for (int i = 0; i < size; i++) {
        sum += (arr[i] - mean) * (arr[i] - mean);
    }
    return sqrt(sum / size);
}

double calculatePercentile(double arr[], int size, double p) {
    if (p < 0 || p > 100) {
        exit(EXIT_FAILURE);
    }

    // Sort the array
    qsort(arr, size, sizeof(double), compare);

    // Calculate the index
    double index = (p / 100.0) * (size - 1);
    int lower = (int)index;
    int upper = lower + 1;

    // If the index is an integer, return the value at that index
    if (lower == upper) {
        return arr[lower];
    } else {
        // Interpolate between lower and upper
        double fraction = index - lower;
        return arr[lower] + fraction * (arr[upper] - arr[lower]);
    }
}

