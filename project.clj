(defproject com.middlesphere/msprandom "0.5.2"
  :description "Random numbers generator: library is intended to generate cryptographically strong random numbers."
  :url "https://github.com/middlesphere/msprandom.git"
  :vendor "Middlesphere"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [jline "2.11"]] ;keyboard library
  :target-path "target/%s/"
  :omit-source false
            ;:global-vars {*warn-on-reflection* true}
  :profiles {
             :dev      {:dependencies [[org.bouncycastle/bcprov-jdk15on "1.52"]]}
             :provided {:dependencies [[org.bouncycastle/bcprov-jdk15on "1.52"]]}}
  :scm {:name "git"
        :url "https://github.com/middlesphere/msprandom.git"}
  )
