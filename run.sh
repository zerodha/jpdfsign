#!/bin/bash
java -cp lib/itextpdf-5.5.6.jar:lib/bcprov-jdk15on-152.jar -cp ./bin PdfSigner ${@}
