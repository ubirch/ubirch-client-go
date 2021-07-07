# Prometheus metrics

This implementations is leaned on [this blog](https://gabrieltanner.org/blog/collecting-prometheus-metrics-in-golang).

To ensure our applications' quality, some kind of quality monitoring and quality checks need to be executed. These quality checks often compare a given metric captured from the application e.g. throughput or error rate, with some defined value e.g. error rate < 0,1%.

## Metric types

Prometheus provides four different metric types each with their advantages and disadvantages that make them useful for different use-cases. For the ubirch-go-client we only use Counters and Histograms currently. 

### Counters
Counters:

Counters are a simple metric type that can only be incremented or be reset to zero on restart. It is often used to count primitive data like the total number of requests to a services or number of tasks completed. Most counters are therefore named using the _total suffix e.g. http_requests_total.

````
# Total number of HTTP request
http_requests_total

# Total number of completed jobs
jobs_completed_total
````

The absolute value of these counters is often irrelevant and does not give you much information about the applications state. The real information can be gathered by their evolution over time which can be obtained using the rate() function.

### Histograms:

Histograms are used to measure the frequency of value observations that fall into specific predefined buckets. This means that they will provide information about the distribution of a metric like response time and signal outliers.

By default Prometheus provides the following buckets: .005, .01, .025, .05, .075, .1, .25, .5, .75, 1, 2.5, 5, 7.5, 10. These buckets are not suitable for every measurement and can therefore easily be changed. 

## Ubirch Go Client Metrics

The ubirch-go-client provides an endpoint for prometheus on:

`/metrics`

You can find all necessary data int the `main/prometheus` package. There we provide a middleware which can be added to the router to wrap all endpoints with the defined metrics. Currently we collect those metrics:

 - **http_requests_total**: the total number of HTTP requests made to the server per path represented in a counter. 
- **response_status**: the responses to the client made by the server as counter.
- **http_response_time_seconds**: the amount of time passed for the server to process the request and response per path collected as historgram. 

