import os
import logging
import vuln_scanner.java_analyser as java_analyser

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_jar_gav_extraction(jar_path):
    logger.info(f"\n--- Testing GAV Extraction for JAR: {jar_path} ---")
    try:
        with open(jar_path, 'rb') as f:
            jar_content_bytes = f.read()
        
        jar_filename_for_logging = os.path.basename(jar_path)
        
        # Call the main GAV extraction function
        gav_data = java_analyser.extract_gav_from_jar_bytes(jar_content_bytes, jar_filename_for_logging)
        
        logger.info("\n>>> Consolidated GAV Data: <<<")
        if gav_data:
            logger.info(f"  GroupId:    {gav_data.get('groupId')}")
            logger.info(f"  ArtifactId: {gav_data.get('artifactId')}")
            logger.info(f"  Version:    {gav_data.get('version')}")
            logger.info(f"  Sources:    {gav_data.get('source')}")
            logger.info(f"  Full Data:  {gav_data}")
        else:
            logger.info("Could not extract any GAV data.")

    except FileNotFoundError:
        logger.error(f"Error: JAR file not found at {jar_path}")
    except Exception as e:
        logger.error(f"An error occurred during GAV extraction for {jar_path}: {e}", exc_info=True)

def test_war_file_analysis(war_path):
    logger.info(f"\n--- Analyzing WAR file: {war_path} ---")
    try:
        all_gavs_in_war = java_analyser.analyze_war_file(war_path)

        logger.info(f"\n>>> Found {len(all_gavs_in_war)} libraries in {os.path.basename(war_path)}: <<<")
        for idx, gav_data in enumerate(all_gavs_in_war):
            logger.info(f"  Lib {idx+1}:")
            logger.info(f"    File in WAR: {gav_data.get('filename_in_archive')}")
            logger.info(f"    GroupId:     {gav_data.get('groupId')}")
            logger.info(f"    ArtifactId:  {gav_data.get('artifactId')}")
            logger.info(f"    Version:     {gav_data.get('version')}")
            logger.info(f"    Sources:     {gav_data.get('source')}")
            logger.info(f"    Full GAV:    {gav_data}")
    except FileNotFoundError:
        logger.error(f"Error: WAR file not found at {war_path}")
    except Exception as e:
        logger.error(f"An error occurred during WAR analysis for {war_path}: {e}", exc_info=True)

def test_spring_boot_jar_analysis(sb_jar_path):
    logger.info(f"\n--- Analyzing Spring Boot JAR: {sb_jar_path} ---")
    try:
        all_gavs_in_sb_jar = java_analyser.analyze_spring_boot_jar(sb_jar_path)

        logger.info(f"\n>>> Found {len(all_gavs_in_sb_jar)} libraries in {os.path.basename(sb_jar_path)}: <<<")
        for idx, gav_data in enumerate(all_gavs_in_sb_jar):
            logger.info(f"  Lib {idx+1}:")
            logger.info(f"    File in SB JAR: {gav_data.get('filename_in_archive')}")
            logger.info(f"    GroupId:        {gav_data.get('groupId')}")
            logger.info(f"    ArtifactId:     {gav_data.get('artifactId')}")
            logger.info(f"    Version:        {gav_data.get('version')}")
            logger.info(f"    Sources:        {gav_data.get('source')}")
            logger.info(f"    Full GAV:       {gav_data}")
    except FileNotFoundError:
        logger.error(f"Error: Spring Boot JAR file not found at {sb_jar_path}")
    except Exception as e:
        logger.error(f"An error occurred during Spring Boot JAR analysis for {sb_jar_path}: {e}", exc_info=True)

if __name__ == "__main__":
    test_jar_files = [#'commons-io-2.11.0.jar',
                      #'log4j-1.2.17.jar',            
                      #org.apache.felix.framework-7.0.5.jar',
                      #'commons-io-no-pom-xml.jar',
                      #'commons-io-only-manifest.jar'
    ] 

    sample_war_filepath = 'jenkins.war'
    if not os.path.exists(sample_war_filepath) or sample_war_filepath == 'path/to/your/sample.war':
        logger.warning(f"WAR TEST SKIPPED: WAR file not found or path not updated: '{sample_war_filepath}'.")
    else:
        test_war_file_analysis(sample_war_filepath)
    logger.info("-" * 70)
 
    # Test a Spring Boot JAR file
    sample_sb_jar_filepath = 'spring-petclinic-3.4.0-SNAPSHOT.jar' # <--- Path to your downloaded petclinic.jar
    if not os.path.exists(sample_sb_jar_filepath) or sample_sb_jar_filepath == 'path/to/your/spring_boot.jar':
        logger.warning(f"SPRING BOOT JAR TEST SKIPPED: JAR file not found or path not updated: '{sample_sb_jar_filepath}'.")
    else:
        test_spring_boot_jar_analysis(sample_sb_jar_filepath)
    logger.info("-" * 70)



'''
    # TODO: Add more test JARs here to test different scenarios:
    # 1. JAR with only MANIFEST.MF (no pom.xml or pom.properties)
    # 2. JAR with pom.properties but no pom.xml
    # 3. JAR with only GAV in parent POM (if you enhance pom.xml parsing for this)
    # 4. JARs with tricky manifest values for G/A
'''