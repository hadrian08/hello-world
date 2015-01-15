<?php
/**
 * Class for tracking request frequency and parallelism -- to prevent DoS, etc.
 *
 * @package   Utilities
 *
 * @author    Richard Pavlicek <rpavlicek@intacct.com>
 * @copyright 2000 Intacct Corporation All, Rights Reserved
 *
 */

/**
 * Class for tracking request frequency
 */
class RequestMonitor
{
    /**
     * @var checkedAggregate flag that indicates if we checked the aggregate for this request
     */
    private static $checkedAggregate = false;

    /**
     * @var checkedParallel flag that indicates if we checked the parallelism for this request
     */
    private static $checkedParallel = false;

    /**
     * @var weight of this URL as determined from the configuration and script name
     */
    private static $weightParallel = 0;

    /**
     * @var array $config is the loaded configuration
     */
    private static $config = null;

    /**
     * isExempt
     *
     * Checks for various conditions that give this request an exempt status
     *
     * @return true if this request is exempt, false otherwise
     */
    private static function isExempt()
    {
        // Only run this if we are inside an Apache environment and we have an OID
        if ( ! isset($_SERVER['UNIQUE_ID']) || ! isset($_COOKIE['_oid']) ) {
            return true;
        }

        // Allowed scripts that do not test the threshold
        $exemptURLs = array(
            'xmlgw.phtml',
            'imsq.phtml',
            'pt_pf.phtml',
        );

        // Check allowed scripts that automatically pass through
        $scriptName = ScriptName();
        if ( in_array($scriptName, $exemptURLs) ) {
            return true;
        }

        // Check for local client request (127.0.0.1)
        if ( $_SERVER['REMOTE_ADDR'] == '127.0.0.1' ) {
            return true;
        }

        return false;
    }


    /**
     * extractGroupData
     *
     * Takes an input str in the format "key:val,key:val,etc.."
     *
     * @return an array of data upon success, false otherwise
     */
    private static function extractGroupData($group)
    {
        $extracted = array();
        $pairs = explode(',',$group);
        foreach ( $pairs as $pairStr ) {
            $pair = explode(':', $pairStr);
            $key = $pair[0];
            $val = $pair[1];
            if ( isset($key) && isset($val) ) {
                $extracted[$key] = $val;
            }
        }

        return $extracted;
    }

    /**
     * getAggregateConfiguration
     *
     * Gets the aggregate configuration data from ia_init.cfg
     *
     * @return an array of data upon success, false otherwise
     */
    private static function getAggregateConfiguration()
    {
        // get configuration data
        $thresholdConfigArray = GetValueForIACFGProperty("TMR_THRESHOLD");
        if ( !is_array($thresholdConfigArray) ) {
            return false;
        }

        // Determine the threshold arrays
        $thresholdArray = self::extractGroupData($thresholdConfigArray['TMR_THRESHOLD_GROUPS']);
        $maxNumIntervals = 0;
        foreach ( $thresholdArray as $numIntervals => $val ) {
            if ($numIntervals > $maxNumIntervals ) {
                $maxNumIntervals = $numIntervals;
            }
        }

        // Don't do anything if there is nothing to check (if config data is missing or badly formed, this will also return here)
        if ( count($thresholdArray) < 1 ) {
            return false;
        }

        $thresholdInterval    = isset($thresholdConfigArray['TMR_THRESHOLD_INTERVAL']) ? $thresholdConfigArray['TMR_THRESHOLD_INTERVAL'] : 3;
        $thresholdExpiration  = $maxNumIntervals * $thresholdInterval + 10;

        $weightedURLs = self::extractGroupData($thresholdConfigArray['TMR_THRESHOLD_WEIGHTS']);

        $debug = ( intval($thresholdConfigArray['TMR_THRESHOLD_DEBUG']) === 1 );

        return array(
            'groups'     => $thresholdArray,
            'interval'   => $thresholdInterval,
            'expiration' => $thresholdExpiration,
            'maxnumint'  => $maxNumIntervals,
            'weights'    => $weightedURLs,
            'debug'      => $debug,
        );
    }

    /**
     * checkAggregateThreshold
     *
     * Checks total requests made over a period of time, without regard to parallelism
     *
     * @return true if threshold has been exceeded, false otherwise
     */
    public static function checkAggregateThreshold()
    {
        $t = array(); // add this to lines for debug timing: $t[__LINE__] = microtime(true); // ***REMOVE
        static $source = "checkAggregateThreshold";

        // Check if we have been called before (this should be called max once per process)
        if ( self::$checkedAggregate ) {
            return false;
        } else {
            self::$checkedAggregate = true;
        }

        // Check to see if this request is exempt
        if ( self::isExempt() ) {
            return false;
        }

        StartTimer($source);

        // get configuration data
        $config = self::getAggregateConfiguration();
        if ( $config === false ) {
            return false;
        }

        $thresholdArray = $config['groups'];
        $thresholdInterval = $config['interval'];
        $thresholdExpiration = $config['expiration'];

        // Lets break the instances into intervals
        $timeChunkRemove = 1314159265; // equivalent to strtotime('2011-08-23 21:14:25'), use this to reduce size of data structure for serialization

        // This interval key also represents the current 'now' interval, which is used as a reference for other intervals
        $intervalKey = intval((time() - $timeChunkRemove) / $thresholdInterval);


        /** The data structure is a key/value pair of interval Key to number of requests in that interval:
         *
         * array(
         *     210 => 300,
         *     211 => 200,
         *     212 => 700,
         *     213 => 20000,   <--- spike
         *     214 => 200,
         *                          <--- missing interval (normal)
         *     216 => 100,
         * );
         *
         */

        // Check if this is an ajax request through the .action POST parameter
        $weightedScriptName = ($_POST['_action'] == 'ajax') ? 'GENERIC_AJAX' : ScriptName();

        // Weighted URLS
        $weightedURLS = $config['weights'];

        // Determine the weight of this URL
        $weight = isset($weightedURLS[$weightedScriptName]) ? $weightedURLS[$weightedScriptName] : 100;

        // Get the previous data (if any)
        $mc = MemcacheClient::getInstance(null, MemcacheClient::GLOBAL_POOL);
        $keyName = 'TMR_A_' . $_COOKIE['_oid'];

        $rawData = $mc->get($keyName);
        if ( $rawData ) {
            $intervalStruct = unserialize($rawData);
        } else {
            $intervalStruct = array();
        }

        // Increment this intervals count
        if ( isset($intervalStruct[$intervalKey]) ) {
            $intervalStruct[$intervalKey] += $weight;
        } else {
            $intervalStruct[$intervalKey] = $weight;
        }

        // Loop through all intervals to clear old data
        foreach ( $intervalStruct as $keyTime => $count ) {
            if ( ($intervalKey - $keyTime) > $config['maxnumint'] ) {
                // Remove old data
                unset($intervalStruct[$keyTime]);
            }
        }

        // Store the data
        $rawData = serialize($intervalStruct);
        $mc->set($keyName, $rawData, $thresholdExpiration);

        // Find if any limits were exceeded
        $countRequests = array();
        $exceededThresholds = array();
        $thresholdExceeded = false;
        foreach ( $intervalStruct as $keyTime => $weight ) {
            foreach ( $thresholdArray as $numIntervals => $weightLimit ) {
                if ( ($intervalKey - $keyTime) < $numIntervals ) {
                    $countRequests[$numIntervals] =
                        isset($countRequests[$numIntervals])
                            ? $countRequests[$numIntervals] + $weight
                            : $weight;
                    if ( $countRequests[$numIntervals] > $weightLimit ) {
                        $thresholdExceeded = true;
                        $exceededThresholds[$numIntervals] = $countRequests[$numIntervals];
                    }
                }
            }
        }

        // Check if a threshold limit was reached
        if ( $thresholdExceeded ) {
            $thresholdStrInfo = '';
            $first = 0;
            foreach ( $exceededThresholds as $numIntervals => $weight ) {
                $first++;
                $preStr = '';
                if ( $first != 1 ) {
                    $preStr = ', ';
                }
                $thresholdExceeded = true;
                $weightLimit = $thresholdArray[$numIntervals];
                $thresholdStrInfo .= $preStr . "$numIntervals:$weightLimit/$weight";
            }
            $strData = 'Interval=' . $thresholdInterval
                . '; SESS=' . $_REQUEST['_sess']
                . '; OID=' . $_COOKIE['_oid']
                . '; IP=' . $_SERVER['REMOTE_ADDR']
                . '; Thresholds exceeded: '
                . $thresholdStrInfo;
            // Write something to log to indicate a limit was reached
            logToFile("WARNING (TMR): Too many requests: " . $strData . "\n");
        }

        StopTimer($source);

        // Debugging
        $debug = $config['debug'];
        if ( $debug ) {
            $msg = "DEBUG INFO (TMR): ";
            foreach ( $thresholdArray as $numIntervals => $weightLimit ) {
                $weight = $countRequests[$numIntervals];
                $msg .= "I/L/C=$numIntervals/$weightLimit/$weight;";
            }
            logToFile("$msg\n");

            $countElements = count($intervalStruct);
            $size = strlen($rawData);
            logToFile("$source ran for " . GetTimer($source) . " seconds\n");
            logToFile("$source data structure has " . $countElements . " item(s), which takes " . $size . " bytes\n");
        }

        return $thresholdExceeded;
    }


    /**
     * getParallelConfiguration
     *
     * Gets the parallel configuration data from ia_init.cfg
     *
     * @return an array of data upon success, false otherwise
     */
    private static function getParallelConfiguration()
    {
        // get configuration data
        $thresholdConfigArray = GetValueForIACFGProperty("TMPR_THRESHOLD");
        if ( !is_array($thresholdConfigArray) || !isset($thresholdConfigArray['TMPR_THRESHOLD_LIMIT']) ) {
            return false;
        }

        // If the limit is 0 or less, just return (no point in checking)
        $parallelLimit = intval($thresholdConfigArray['TMPR_THRESHOLD_LIMIT']);
        if ( $parallelLimit < 1 ) {
            return false;
        }

        $parallelTimeout = isset($thresholdConfigArray['TMPR_THRESHOLD_TIMEOUT'])
            ? intval($thresholdConfigArray['TMPR_THRESHOLD_TIMEOUT'])
            : 300;

        $weightedURLs = self::extractGroupData($thresholdConfigArray['TMPR_THRESHOLD_WEIGHTS']);

        $debug = ( intval($thresholdConfigArray['TMPR_THRESHOLD_DEBUG']) === 1 );

        return array(
            'limit'   => $parallelLimit,
            'timeout' => $parallelTimeout,
            'weights' => $weightedURLs,
            'debug'   => $debug);
    }

    /**
     * checkParallelThreshold
     *
     * Checks total requests allowed in parallel
     *
     * @return true if threshold has been exceeded, false otherwise
     */
    public static function checkParallelThreshold()
    {
        $t = array(); // add this to lines for debug timing: $t[__LINE__] = microtime(true);
        static $source = "checkParallelThreshold";

        // Check if we have been called before (this should be called max once per process)
        if ( self::$checkedParallel ) {
            return false;
        } else {
            self::$checkedParallel = true;
        }

        // Check to see if this request is exempt
        if ( self::isExempt() ) {
            return false;
        }

        $config = self::getParallelConfiguration();
        if ( $config === false ) {
            return false;
        }

        self::$config = $config;

        StartTimer($source);

        $exceededLimit = false;

        // Check if this is an ajax request through the .action POST parameter
        $weightedScriptName = ($_POST['_action'] == 'ajax') ? 'GENERIC_AJAX' : ScriptName();

        // Weighted URLS
        $weightedURLS = $config['weights'];

        // Determine the weight of this URL
        self::$weightParallel = isset($weightedURLS[$weightedScriptName]) ? $weightedURLS[$weightedScriptName] : 100;

        // Use interlocked increment on the memcache key
        $mc = MemcacheClient::getInstance(null, MemcacheClient::GLOBAL_POOL);
        $keyName = 'TMR_P_' . $_COOKIE['_oid'];

        $weightTotal = $mc->interlockedIncrement($keyName, $config['timeout'], self::$weightParallel);
        if ( $weightTotal === false ) {
            return false;
        }

        // Register the function that will decrement this requests count (once finished)
        register_shutdown_function(array('RequestMonitor', 'finishParallelRequest'));

        if ( $weightTotal > $config['limit'] ) {
            $strData = 'SESS=' . $_REQUEST['_sess']
                . '; OID=' . $_COOKIE['_oid']
                . '; IP=' . $_SERVER['REMOTE_ADDR']
                . '; Limit/Weight=' . $config['limit'] . '/' . $weightTotal;
            // Write something to log to indicate a limit was reached
            logToFile("WARNING (TMPR): Parallel request limit exceeded: " . $strData . "\n");
            $exceededLimit = true;
        }

        StopTimer($source);

        // Debugging
        $debug = $config['debug'];
        if ( $debug ) {
            logToFile("DEBUG INFO (TMPR): + $keyName Limit/Weight(request)/Weight(total)=" . $config['limit'] . "/" . self::$weightParallel . "/$weightTotal\n");
            logToFile("$source ran for " . GetTimer($source) . " seconds\n");
        }

        return $exceededLimit;
    }

    /**
     * finishParallelRequest
     *
     * Function called during shutdown to decrement the parallel counter for this user/oid
     *
     * @return void
     */
    public static function finishParallelRequest()
    {
        if ( self::$checkedParallel ) {
            // Use interlocked decrement on the memcache key
            $mc = MemcacheClient::getInstance(null, MemcacheClient::GLOBAL_POOL);
            $keyName = 'TMR_P_' . $_COOKIE['_oid'];

            $parallelCount = $mc->interlockedDecrement($keyName, 0, self::$weightParallel, false);
            if ( $parallelCount === false ) {
                $parallelCount = "false";
            }

            $debug = self::$config['debug'];
            if ( $debug ) {
                logToFile(  "DEBUG INFO (TMPR): - $keyName Limit/Weight(request)/Weight(total)="
                          . self::$config['limit'] . "/" . self::$weightParallel . "/$parallelCount\n");
            }
        } else {
            // Log a warning, this shouldn't be called unless checkParallelThreshold was called earlier
            logToFile("Warning: finishParallelRequest called without checkParallelThreshold\n");
        }
    }


}