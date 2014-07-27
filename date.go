package gav

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"
)

/*
 *  Simple function to put a correct time/date stamp into the header
 *	Parm:	Pointer to http.Request to modify
 *  return: pointer to Secure for chaining
 */
func ( s * Secure ) SetSignatureDate( r * http.Request ) * Secure {
	r.Header.Del( GAV_HEADER_TIMESTAMP )
	r.Header.Set( GAV_HEADER_TIMESTAMP , time.Now().UTC().Format( http.TimeFormat) )
	return s
}

/*
 *  Get Signature date from header unless it falls outside of the maximum time slots
 *  If the date is within the range, then you get a string. If it is outside of range
 *  or doesn't exist, you get an error return
 *	Parm:	Pointer to http.Request to modify
 *  return: Date/time string
 *			error message or nil on no error
 */
func ( s * Secure )GetSignatureDate( r *http.Request)( string ,error ){

	requestDate := r.Header.Get( GAV_HEADER_TIMESTAMP )		// Header has "Timestamp:"
	if len(requestDate) == 0 {					// Umm..NO
		requestDate = r.Header.Get( GAV_HEADER_DATE )		// Header has "Date:" ?

		if len(requestDate ) == 0 {
			return "" , errors.New( TIMESTAMP_MISSING )
		}
	}
	// Check to see if timestamp is older than 15min. If so, reject request
	// First, parse this into a time object...
	tstamp , err := http.ParseTime( requestDate )	// Always use this parser as it does 3 formats...
	if err != nil {
		return "" , err
	}
	// Now...see what the difference is between NOW and the HTTP date
	diff := math.Abs( time.Now().Sub( tstamp ).Minutes())		// We want how far in the past it is...

	if diff > s.TimeWindow.Minutes()  {
		return "",fmt.Errorf("%s - %.0f min. max/%.0f in header" ,
			TIMESTAMP_RANGE , s.TimeWindow.Minutes() , diff )
	}
	return requestDate , nil						// Passed all tests...
}
